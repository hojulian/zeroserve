use async_ebpf::program::HelperScope;

use crate::script::{deref_and_write_cstr, read_utf8, with_ectx};

/// Helper: `zs_kv_get(key, key_len, out, out_len) -> i64`
///
/// Look up `key` in the server-managed key-value map (populated from `--kv-map-file`).
/// Returns the number of bytes written into `out`, 0 if the key is not found,
/// or -1 on error (invalid memory, no map configured).
/// The result is NOT null-terminated.
pub fn h_kv_get(
    scope: &HelperScope,
    key_ptr: u64,
    key_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = match read_utf8(scope, key_ptr, key_len) {
        Ok(k) if !k.is_empty() => k.to_string(),
        _ => return Ok(-1i64 as u64),
    };

    // Returns Ok(None) = no map configured (-1), Ok(Some(None)) = key not found (0),
    // Ok(Some(Some(v))) = found.
    let lookup = with_ectx(scope, |ctx| {
        let Some(ref kv_map) = ctx.kv_map else {
            return Ok(None::<Option<String>>);
        };
        Ok(Some(kv_map.get(&key)))
    })?;

    match lookup {
        None => Ok(-1i64 as u64),           // no map configured
        Some(None) => Ok(0),                // key not found
        Some(Some(v)) => {
            deref_and_write_cstr(scope, out_ptr, out_len, &v)
        }
    }
}
