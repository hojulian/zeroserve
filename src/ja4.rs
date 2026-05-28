use sha2::{Digest, Sha256};

const EXT_SNI: u16 = 0x0000;
const EXT_ALPN: u16 = 0x0010;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

#[derive(Clone, Copy)]
struct Extension<'a> {
    ty: u16,
    body: &'a [u8],
}

/// Compute the JA4 TLS-over-TCP client fingerprint from a serialized
/// ClientHello. Accepts either the handshake body or the full handshake message
/// prefixed by type and length.
pub fn tls_client_fingerprint(client_hello: &[u8]) -> Option<String> {
    let hello = strip_handshake_header(client_hello).unwrap_or(client_hello);
    let parsed = parse_client_hello(hello)?;

    let version = ja4_version(parsed.supported_version.unwrap_or(parsed.legacy_version));
    let sni_marker = if parsed.extensions.iter().any(|ext| ext.ty == EXT_SNI) {
        "d"
    } else {
        "i"
    };

    let ciphers: Vec<u16> = parsed
        .ciphers
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();
    let cipher_count = two_digit_count(ciphers.len());
    let extension_count = two_digit_count(
        parsed
            .extensions
            .iter()
            .filter(|ext| !is_grease(ext.ty))
            .count(),
    );
    let alpn = parsed
        .extensions
        .iter()
        .find(|ext| ext.ty == EXT_ALPN)
        .and_then(|ext| alpn_marker(ext.body))
        .unwrap_or_else(|| "00".to_string());

    let cipher_hash = hash_list_or_zero(&sorted_hex_list(&ciphers));

    let extension_values: Vec<u16> = parsed
        .extensions
        .iter()
        .map(|ext| ext.ty)
        .filter(|v| !is_grease(*v) && *v != EXT_SNI && *v != EXT_ALPN)
        .collect();
    let extension_list = sorted_hex_list(&extension_values);
    let extension_hash = if extension_list.is_empty() {
        "000000000000".to_string()
    } else {
        let sig_algs = parsed
            .extensions
            .iter()
            .find(|ext| ext.ty == EXT_SIGNATURE_ALGORITHMS)
            .map(|ext| signature_algorithms(ext.body))
            .unwrap_or_default();
        let sig_alg_list = original_hex_list(&sig_algs);
        let hash_input = if sig_alg_list.is_empty() {
            extension_list
        } else {
            format!("{extension_list}_{sig_alg_list}")
        };
        truncated_sha256(&hash_input)
    };

    Some(format!(
        "t{version}{sni_marker}{cipher_count}{extension_count}{alpn}_{cipher_hash}_{extension_hash}"
    ))
}

struct ParsedClientHello<'a> {
    legacy_version: u16,
    supported_version: Option<u16>,
    ciphers: Vec<u16>,
    extensions: Vec<Extension<'a>>,
}

fn parse_client_hello(input: &[u8]) -> Option<ParsedClientHello<'_>> {
    let mut reader = Reader::new(input);
    let legacy_version = reader.u16()?;
    reader.bytes(32)?;
    let session_id_len = reader.u8()? as usize;
    reader.bytes(session_id_len)?;

    let ciphers_len = reader.u16()? as usize;
    if ciphers_len % 2 != 0 {
        return None;
    }
    let ciphers_bytes = reader.bytes(ciphers_len)?;
    let ciphers = read_u16_list(ciphers_bytes);

    let compression_len = reader.u8()? as usize;
    reader.bytes(compression_len)?;

    let extensions = if reader.remaining().is_empty() {
        Vec::new()
    } else {
        let extensions_len = reader.u16()? as usize;
        let extensions_bytes = reader.bytes(extensions_len)?;
        if !reader.remaining().is_empty() {
            return None;
        }
        parse_extensions(extensions_bytes)?
    };

    let supported_version = extensions
        .iter()
        .find(|ext| ext.ty == EXT_SUPPORTED_VERSIONS)
        .and_then(|ext| supported_versions_max(ext.body));

    Some(ParsedClientHello {
        legacy_version,
        supported_version,
        ciphers,
        extensions,
    })
}

fn strip_handshake_header(input: &[u8]) -> Option<&[u8]> {
    if input.len() < 4 || input[0] != 1 {
        return None;
    }
    let len = ((input[1] as usize) << 16) | ((input[2] as usize) << 8) | input[3] as usize;
    (input.len() == len + 4).then_some(&input[4..])
}

fn parse_extensions(mut input: &[u8]) -> Option<Vec<Extension<'_>>> {
    let mut out = Vec::new();
    while !input.is_empty() {
        if input.len() < 4 {
            return None;
        }
        let ty = u16::from_be_bytes([input[0], input[1]]);
        let len = u16::from_be_bytes([input[2], input[3]]) as usize;
        input = &input[4..];
        if input.len() < len {
            return None;
        }
        let (body, rest) = input.split_at(len);
        out.push(Extension { ty, body });
        input = rest;
    }
    Some(out)
}

fn supported_versions_max(body: &[u8]) -> Option<u16> {
    let (&len, rest) = body.split_first()?;
    let versions = rest.get(..len as usize)?;
    if versions.len() % 2 != 0 {
        return None;
    }
    read_u16_list(versions)
        .into_iter()
        .filter(|v| !is_grease(*v))
        .max()
}

fn signature_algorithms(body: &[u8]) -> Vec<u16> {
    let Some((&len_hi, rest)) = body.split_first() else {
        return Vec::new();
    };
    let Some((&len_lo, rest)) = rest.split_first() else {
        return Vec::new();
    };
    let len = u16::from_be_bytes([len_hi, len_lo]) as usize;
    let Some(values) = rest.get(..len) else {
        return Vec::new();
    };
    if values.len() % 2 != 0 {
        return Vec::new();
    }
    read_u16_list(values)
        .into_iter()
        .filter(|v| !is_grease(*v))
        .collect()
}

fn alpn_marker(body: &[u8]) -> Option<String> {
    if body.len() < 3 {
        return None;
    }
    let list_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let list = body.get(2..2 + list_len)?;
    let (&first_len, rest) = list.split_first()?;
    if first_len == 0 {
        return None;
    }
    let first = rest.get(..first_len as usize)?;
    let first_byte = *first.first()?;
    let last_byte = *first.last()?;
    if first_byte.is_ascii_alphanumeric() && last_byte.is_ascii_alphanumeric() {
        let mut out = String::with_capacity(2);
        out.push(first_byte as char);
        out.push(last_byte as char);
        return Some(out);
    }
    Some(format!("{:02x}", first_byte)[..1].to_string() + &format!("{:02x}", last_byte)[1..2])
}

fn read_u16_list(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect()
}

fn sorted_hex_list(values: &[u16]) -> String {
    let mut values = values.to_vec();
    values.sort_unstable();
    original_hex_list(&values)
}

fn original_hex_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn hash_list_or_zero(list: &str) -> String {
    if list.is_empty() {
        "000000000000".to_string()
    } else {
        truncated_sha256(list)
    }
}

fn truncated_sha256(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    hex_prefix(&digest, 12)
}

fn hex_prefix(bytes: &[u8], chars: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(chars);
    for &byte in bytes {
        if out.len() == chars {
            break;
        }
        out.push(HEX[(byte >> 4) as usize] as char);
        if out.len() == chars {
            break;
        }
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn ja4_version(version: u16) -> &'static str {
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

fn two_digit_count(count: usize) -> String {
    format!("{:02}", count.min(99))
}

fn is_grease(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && (low & 0x0f) == 0x0a
}

struct Reader<'a> {
    input: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    fn remaining(&self) -> &'a [u8] {
        self.input
    }

    fn u8(&mut self) -> Option<u8> {
        let (&value, rest) = self.input.split_first()?;
        self.input = rest;
        Some(value)
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.bytes(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.input.len() < len {
            return None;
        }
        let (head, tail) = self.input.split_at(len);
        self.input = tail;
        Some(head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_reference_example() {
        let ciphers: [u16; 15] = [
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let sig_algs: [u16; 8] = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let mut extensions = Vec::new();
        push_ext(&mut extensions, 0x001b, &[]);
        push_ext(&mut extensions, EXT_SNI, &[0x00, 0x00]);
        push_ext(&mut extensions, 0x0033, &[]);
        push_ext(&mut extensions, EXT_ALPN, &[0x00, 0x03, 0x02, b'h', b'2']);
        push_ext(&mut extensions, 0x4469, &[]);
        push_ext(&mut extensions, 0x0017, &[]);
        push_ext(&mut extensions, 0x002d, &[]);
        let mut sig_body = Vec::new();
        sig_body.extend_from_slice(&((sig_algs.len() * 2) as u16).to_be_bytes());
        for value in sig_algs {
            sig_body.extend_from_slice(&value.to_be_bytes());
        }
        push_ext(&mut extensions, EXT_SIGNATURE_ALGORITHMS, &sig_body);
        push_ext(&mut extensions, 0x0005, &[]);
        push_ext(&mut extensions, 0x0023, &[]);
        push_ext(&mut extensions, 0x0012, &[]);
        push_ext(&mut extensions, EXT_SUPPORTED_VERSIONS, &[0x02, 0x03, 0x04]);
        push_ext(&mut extensions, 0xff01, &[]);
        push_ext(&mut extensions, 0x000b, &[]);
        push_ext(&mut extensions, 0x000a, &[]);
        push_ext(&mut extensions, 0x0015, &[]);

        let mut hello = Vec::new();
        hello.extend_from_slice(&0x0303u16.to_be_bytes());
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        for value in ciphers {
            hello.extend_from_slice(&value.to_be_bytes());
        }
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        assert_eq!(
            tls_client_fingerprint(&hello).as_deref(),
            Some("t13d1516h2_8daaf6152771_e5627efa2ab1")
        );
    }

    #[test]
    fn ignores_grease_for_counts_and_hashes() {
        let mut extensions = Vec::new();
        push_ext(&mut extensions, 0x0a0a, &[]);
        push_ext(
            &mut extensions,
            EXT_SUPPORTED_VERSIONS,
            &[0x04, 0x1a, 0x1a, 0x03, 0x04],
        );

        let mut hello = Vec::new();
        hello.extend_from_slice(&0x0303u16.to_be_bytes());
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&4u16.to_be_bytes());
        hello.extend_from_slice(&0x0a0au16.to_be_bytes());
        hello.extend_from_slice(&0x1301u16.to_be_bytes());
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let fingerprint = tls_client_fingerprint(&hello).unwrap();
        assert!(fingerprint.starts_with("t13i010100_"));
    }

    fn push_ext(out: &mut Vec<u8>, ty: u16, body: &[u8]) {
        out.extend_from_slice(&ty.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
    }
}
