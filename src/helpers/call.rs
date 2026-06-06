use std::any::Any;

use async_ebpf::program::{HelperScope, PreemptionEnabled};

use crate::{
    helpers::estimate_json_memory_usage,
    json::JsonRef,
    script::{
        MAX_CALL_DEPTH, MonoioTimeslicer, SCRIPT_CALL_SECTION_PREFIX, ScriptExecutionContext,
        default_timeslice, read_utf8, with_ectx,
    },
};

/// Why an inter-script call did not produce a result. All of these surface to
/// the caller as a `-1` return from `zs_call` (a normal, handleable value), with
/// the detail recorded in the caller's `ctx.error` for the runtime log.
#[derive(Debug)]
enum CallError {
    /// No loaded script matched the requested name.
    ScriptNotFound,
    /// The target script exists but exports no `zeroserve.call.<func>` section.
    FuncNotFound,
    /// The callee trapped or exceeded its resource budget while running.
    RunFailed,
    /// The callee returned a negative handle (its own signalled failure).
    CalleeError,
    /// The callee returned a handle that is not a live JSON object.
    BadReturn,
}

/// `zs_call(script, script_len, func, func_len, json_handle)` — invoke another
/// script's `zeroserve.call.<func>` entrypoint, passing a JSON handle and
/// receiving one back.
///
/// The input JSON is deep-copied into a fresh execution context for the callee
/// (handle `1`), so the two scripts never share mutable state; the callee's
/// returned JSON is likewise copied back into the caller's object table as a new
/// handle. Returns that new handle on success, or `-1` if the call could not be
/// completed (unknown script/function, callee failure, depth limit). The two
/// string arguments pair with `ZS_STR`, e.g.
/// `zs_call(ZS_STR("greeter"), ZS_STR("greet"), payload)`.
pub fn h_call(
    scope: &HelperScope,
    script_ptr: u64,
    script_len: u64,
    func_ptr: u64,
    func_len: u64,
    json_handle: u64,
) -> Result<u64, ()> {
    let script_name = read_utf8(scope, script_ptr, script_len)?.to_string();
    let func_name = read_utf8(scope, func_ptr, func_len)?.to_string();

    // Snapshot everything the async run needs out of the (borrowed) caller
    // context up front: the borrow cannot survive into the posted task. A bad
    // input handle is a hard error (the script asked for a handle it never
    // received); a depth overflow is a soft `-1` the caller can react to.
    let prepared = with_ectx(scope, |ctx| {
        if ctx.call_depth >= MAX_CALL_DEPTH {
            ctx.error = format!("zs_call: maximum call depth ({}) exceeded", MAX_CALL_DEPTH);
            return Ok(None);
        }
        let input = ctx
            .extobj::<JsonRef>(json_handle)?
            .view(|v| v.clone())
            .map_err(|_| ())?;
        Ok(Some((
            input,
            ctx.scripts.clone(),
            ctx.t,
            ctx.request.clone(),
            ctx.body_source.clone(),
            ctx.site.clone(),
            ctx.call_depth,
            ctx.max_memory_footprint,
        )))
    })?;

    let Some((input, scripts, t, request, body_source, site, call_depth, max_mem)) = prepared
    else {
        return Ok(-1i64 as u64);
    };

    scope.post_task(async move {
        let section = format!("{}{}", SCRIPT_CALL_SECTION_PREFIX, func_name);
        let result: Result<serde_json::Value, CallError> = async {
            let program = scripts
                .iter()
                .find(|(name, _)| {
                    name == &script_name || name.strip_suffix(".o") == Some(script_name.as_str())
                })
                .map(|(_, program)| program)
                .ok_or(CallError::ScriptNotFound)?;

            if !program.has_section(&section) {
                return Err(CallError::FuncNotFound);
            }

            let mut callee = ScriptExecutionContext::for_call(
                input,
                request,
                body_source,
                script_name.clone(),
                site,
                scripts.clone(),
                t,
                max_mem,
                call_depth + 1,
            );
            let timeslice = default_timeslice();
            let preemption = PreemptionEnabled::new(t);
            let ret = {
                let mut resources: [&mut dyn Any; 1] = [&mut callee];
                program
                    .run(
                        &timeslice,
                        &MonoioTimeslicer,
                        &section,
                        &mut resources,
                        &1u64.to_le_bytes(),
                        &preemption,
                    )
                    .await
            };
            drop(preemption);
            let ret = ret.map_err(|_| CallError::RunFailed)?;
            if ret < 0 {
                return Err(CallError::CalleeError);
            }
            callee
                .extobj::<JsonRef>(ret as u64)
                .map_err(|_| CallError::BadReturn)?
                .view(|v| v.clone())
                .map_err(|_| CallError::BadReturn)
        }
        .await;

        move |scope: &HelperScope| match result {
            Ok(value) => with_ectx(scope, |ctx| {
                ctx.alloc_memory_footprint(estimate_json_memory_usage(&value) as u64)?;
                ctx.alloc_extobj(JsonRef::new(value))
            }),
            Err(err) => with_ectx(scope, |ctx| {
                ctx.error = format!("zs_call: '{}' failed: {:?}", section, err);
                Ok(-1i64 as u64)
            }),
        }
    });

    Ok(0)
}
