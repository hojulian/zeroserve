use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, SocketAddr},
};

use anyhow::{Context, bail};
use async_ebpf::program::HelperScope;
use monoio::{
    io::{AsyncReadRentExt, AsyncWriteRentExt},
    net::UnixStream,
};
use serde::{Deserialize, Serialize};

use crate::{
    json::JsonRef,
    script::{read_utf8, with_ectx},
};

const MAX_VICI_SEGMENT_LEN: usize = 512 * 1024;

const CMD_REQUEST: u8 = 0;
const CMD_RESPONSE: u8 = 1;
const CMD_UNKNOWN: u8 = 2;
const EVENT_REGISTER: u8 = 3;
const EVENT_UNREGISTER: u8 = 4;
const EVENT_CONFIRM: u8 = 5;
const EVENT_UNKNOWN: u8 = 6;
const EVENT: u8 = 7;

/// `zs_vici_eap_identity_by_ip(ip, ip_len)`
///
/// Query strongSwan's VICI `list-sas` stream and return a JSON handle for the
/// SA whose `remote-host` or `remote-vips` contains `ip`.
pub fn h_vici_eap_identity_by_ip(
    scope: &HelperScope,
    ip_ptr: u64,
    ip_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let target_ip = match read_utf8(scope, ip_ptr, ip_len)
        .ok()
        .and_then(parse_ip_input)
    {
        Some(ip) => ip,
        None => return Ok(-1i64 as u64),
    };

    let Ok(socket_path) = std::env::var("ZEROSERVE_VICI_SOCKET") else {
        return Ok(-1i64 as u64);
    };
    let Some(socket_path) = normalize_unix_socket_path(&socket_path) else {
        return Ok(-1i64 as u64);
    };

    scope.post_task(async move {
        let result = query_eap_identity_by_ip(socket_path, target_ip).await;
        move |scope: &HelperScope| match result {
            Ok(Some(json)) => with_ectx(scope, |ctx| {
                ctx.alloc_memory_footprint(
                    crate::helpers::estimate_json_memory_usage(&json) as u64
                )?;
                ctx.alloc_extobj(JsonRef::new(json))
            }),
            Ok(None) => Ok(0),
            Err(err) => {
                eprintln!("[vici] zs_vici_eap_identity_by_ip: {err:?}");
                Ok(-1i64 as u64)
            }
        }
    });
    Ok(0)
}

async fn query_eap_identity_by_ip(
    socket_path: String,
    target_ip: IpAddr,
) -> anyhow::Result<Option<serde_json::Value>> {
    let mut stream = UnixStream::connect(&socket_path)
        .await
        .with_context(|| format!("failed to connect to VICI socket '{socket_path}'"))?;

    write_named_packet(&mut stream, EVENT_REGISTER, "list-sa", &[]).await?;
    expect_packet_type(
        read_packet(&mut stream).await?,
        EVENT_CONFIRM,
        "register list-sa",
    )?;

    let request = serde_vici::to_vec(&ListSasRequest { noblock: true })
        .with_context(|| "failed to encode list-sas request")?;
    write_named_packet(&mut stream, CMD_REQUEST, "list-sas", &request).await?;

    let mut found = None;
    loop {
        let packet = read_packet(&mut stream).await?;
        match packet.kind {
            EVENT => {
                if packet.name.as_deref() != Some("list-sa") {
                    continue;
                }
                let event = parse_list_sa_event(&packet.payload)
                    .with_context(|| "failed to parse list-sa event")?;
                if found.is_none() {
                    found = find_matching_sa(&event, target_ip);
                }
            }
            CMD_RESPONSE => break,
            CMD_UNKNOWN => bail!("VICI command 'list-sas' is unknown"),
            EVENT_UNKNOWN => bail!("VICI event 'list-sa' is unknown"),
            other => bail!("unexpected VICI packet type {other} while listing SAs"),
        }
    }

    write_named_packet(&mut stream, EVENT_UNREGISTER, "list-sa", &[]).await?;
    expect_packet_type(
        read_packet(&mut stream).await?,
        EVENT_CONFIRM,
        "unregister list-sa",
    )?;

    Ok(found)
}

#[derive(Serialize)]
struct ListSasRequest {
    noblock: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ViciSa {
    #[serde(default)]
    uniqueid: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    local_host: Option<String>,
    #[serde(default)]
    local_id: Option<String>,
    #[serde(default)]
    remote_host: Option<String>,
    #[serde(default)]
    remote_id: Option<String>,
    #[serde(default)]
    remote_eap_id: Option<String>,
    #[serde(default)]
    remote_vips: Vec<String>,
}

type ListSaEvent = BTreeMap<String, ViciSa>;

fn parse_list_sa_event(payload: &[u8]) -> anyhow::Result<ListSaEvent> {
    serde_vici::from_slice(payload).map_err(Into::into)
}

fn find_matching_sa(event: &ListSaEvent, target_ip: IpAddr) -> Option<serde_json::Value> {
    event.iter().find_map(|(name, sa)| {
        let matched_by = if ip_string_matches(sa.remote_host.as_deref(), target_ip) {
            Some("remote-host")
        } else if sa
            .remote_vips
            .iter()
            .any(|vip| ip_string_matches(Some(vip), target_ip))
        {
            Some("remote-vips")
        } else {
            None
        }?;

        Some(serde_json::json!({
            "identity": sa.remote_eap_id,
            "remote_eap_id": sa.remote_eap_id,
            "remote_id": sa.remote_id,
            "ike_name": name,
            "uniqueid": sa.uniqueid,
            "state": sa.state,
            "local_host": sa.local_host,
            "local_id": sa.local_id,
            "remote_host": sa.remote_host,
            "remote_vips": sa.remote_vips,
            "matched_ip": target_ip.to_string(),
            "matched_by": matched_by,
        }))
    })
}

fn parse_ip_input(input: &str) -> Option<IpAddr> {
    let input = input.trim();
    input
        .parse::<IpAddr>()
        .ok()
        .or_else(|| input.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
        .or_else(|| {
            let (addr, _) = input.split_once('/')?;
            addr.parse::<IpAddr>().ok()
        })
}

fn ip_string_matches(candidate: Option<&str>, target_ip: IpAddr) -> bool {
    candidate.and_then(parse_ip_input) == Some(target_ip)
}

fn normalize_unix_socket_path(input: &str) -> Option<String> {
    let input = input.trim();
    let path = input.strip_prefix("unix://").unwrap_or(input);
    if path.starts_with('/') {
        Some(path.to_string())
    } else {
        None
    }
}

struct Packet {
    kind: u8,
    name: Option<String>,
    payload: Vec<u8>,
}

async fn write_named_packet(
    stream: &mut UnixStream,
    kind: u8,
    name: &str,
    payload: &[u8],
) -> io::Result<()> {
    let name_len = u8::try_from(name.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "VICI packet name too long"))?;
    let mut packet = Vec::with_capacity(2 + name.len() + payload.len());
    packet.push(kind);
    packet.push(name_len);
    packet.extend_from_slice(name.as_bytes());
    packet.extend_from_slice(payload);
    write_segment(stream, packet).await
}

async fn write_segment(stream: &mut UnixStream, packet: Vec<u8>) -> io::Result<()> {
    let len = u32::try_from(packet.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "VICI packet too large"))?;
    let mut frame = Vec::with_capacity(4 + packet.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&packet);
    let (result, _) = stream.write_all(frame).await;
    result.map(|_| ())
}

async fn read_packet(stream: &mut UnixStream) -> anyhow::Result<Packet> {
    let (result, len_buf) = stream.read_exact(vec![0u8; 4]).await;
    result.with_context(|| "failed to read VICI segment length")?;
    let len = u32::from_be_bytes([len_buf[0], len_buf[1], len_buf[2], len_buf[3]]) as usize;
    if len == 0 || len > MAX_VICI_SEGMENT_LEN {
        bail!("invalid VICI segment length {len}");
    }

    let (result, packet) = stream.read_exact(vec![0u8; len]).await;
    result.with_context(|| "failed to read VICI packet")?;
    parse_packet(packet)
}

fn parse_packet(packet: Vec<u8>) -> anyhow::Result<Packet> {
    let Some(kind) = packet.first().copied() else {
        bail!("empty VICI packet");
    };
    let mut payload_offset = 1;
    let name = match kind {
        CMD_REQUEST | EVENT_REGISTER | EVENT_UNREGISTER | EVENT => {
            let Some(name_len) = packet.get(1).copied().map(usize::from) else {
                bail!("named VICI packet missing name length");
            };
            let name_start = 2;
            let name_end = name_start + name_len;
            if packet.len() < name_end {
                bail!("named VICI packet has truncated name");
            }
            payload_offset = name_end;
            Some(
                std::str::from_utf8(&packet[name_start..name_end])
                    .with_context(|| "VICI packet name is not UTF-8")?
                    .to_string(),
            )
        }
        _ => None,
    };

    Ok(Packet {
        kind,
        name,
        payload: packet[payload_offset..].to_vec(),
    })
}

fn expect_packet_type(packet: Packet, expected: u8, action: &str) -> anyhow::Result<()> {
    if packet.kind == expected {
        Ok(())
    } else {
        bail!(
            "unexpected VICI packet type {} during {action}, expected {expected}",
            packet.kind
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ip_literals_socket_addrs_and_cidr() {
        assert_eq!(
            parse_ip_input("192.0.2.10:12345"),
            Some("192.0.2.10".parse().unwrap())
        );
        assert_eq!(
            parse_ip_input("[2001:db8::1]:443"),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            parse_ip_input("10.10.1.67/32"),
            Some("10.10.1.67".parse().unwrap())
        );
    }

    #[test]
    fn normalizes_vici_socket_path_or_uri() {
        assert_eq!(
            normalize_unix_socket_path("unix:///var/run/charon.vici").as_deref(),
            Some("/var/run/charon.vici")
        );
        assert_eq!(
            normalize_unix_socket_path("/run/charon.vici").as_deref(),
            Some("/run/charon.vici")
        );
        assert_eq!(normalize_unix_socket_path("tcp://127.0.0.1:4502"), None);
    }

    #[test]
    fn matches_remote_vip_and_returns_identity_json() {
        let payload = serde_vici::to_vec(&BTreeMap::from([(
            "roadwarrior".to_string(),
            serde_json::json!({
                "uniqueid": "7",
                "state": "ESTABLISHED",
                "remote-host": "203.0.113.20",
                "remote-id": "203.0.113.20",
                "remote-eap-id": "alice@example.com",
                "remote-vips": ["10.10.1.67"],
            }),
        )]))
        .unwrap();
        let event = parse_list_sa_event(&payload).unwrap();
        let json = find_matching_sa(&event, "10.10.1.67".parse().unwrap()).unwrap();

        assert_eq!(json["identity"], "alice@example.com");
        assert_eq!(json["ike_name"], "roadwarrior");
        assert_eq!(json["matched_by"], "remote-vips");
    }

    #[test]
    fn parses_named_packet() {
        let packet = parse_packet(vec![
            EVENT, 7, b'l', b'i', b's', b't', b'-', b's', b'a', 1, 2,
        ])
        .unwrap();
        assert_eq!(packet.kind, EVENT);
        assert_eq!(packet.name.as_deref(), Some("list-sa"));
        assert_eq!(packet.payload, vec![1, 2]);
    }
}
