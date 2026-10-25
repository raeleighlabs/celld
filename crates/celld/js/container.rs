//! Host ops behind `ctx.container`.
//!
//! JavaScript owns the surface and every validation message, copied from
//! workerd's `api/container.c++`; these ops perform the effects through
//! `crate::container`. Each takes the cell scope as its first argument,
//! the way the storage ops do, and an exec process is addressed by the id
//! `__container_exec` returned.

use super::*;
use crate::container::{
    self, AllocationOptions, AllocationRequest, CellContainer, ContainerEngine, ExecParams,
    StartParams,
};
use std::time::Duration;

async fn cell_for(scope: &str) -> Result<(Arc<ContainerEngine>, Arc<CellContainer>), String> {
    let engine = container::engine()
        .await
        .map_err(|error| format!("{error:#}"))?;
    let cell = engine
        .cell(scope)
        .ok_or_else(|| "this Durable Object has no container".to_string())?;
    Ok((engine, cell))
}

fn string_arg(
    scope: &mut v8::PinScope,
    args: &v8::FunctionCallbackArguments,
    index: i32,
) -> String {
    args.get(index).to_rust_string_lossy(scope)
}

fn number_arg(scope: &mut v8::PinScope, args: &v8::FunctionCallbackArguments, index: i32) -> u64 {
    args.get(index).integer_value(scope).unwrap_or(0).max(0) as u64
}

pub(super) fn op_container_running(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let cell = string_arg(scope, &args, 0);
    let running = container::engine_if_ready()
        .and_then(|engine| engine.cell(&cell))
        .is_some_and(|cell| cell.running());
    rv.set(v8::Boolean::new(scope, running).into());
}

/// `host:port` the node dials for `getTcpPort(port)`, or a throw.
pub(super) fn op_container_address(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let cell = string_arg(scope, &args, 0);
    let port = number_arg(scope, &args, 1) as u16;
    match native_access_identity(scope, &cell) {
        Err(error) => return loader_throw(scope, &error),
        Ok(Some(engine)) => {
            match engine.with_allocation_event_cell(
                &cell,
                storage::activation_epoch(&cell),
                |handle| handle.address(port).map_err(anyhow::Error::msg),
            ) {
                Ok(address) => rv.set(v8::String::new(scope, &address).unwrap().into()),
                Err(error) => loader_throw(scope, &format!("{error:#}")),
            }
            return;
        }
        Ok(None) => {}
    }
    let address = container::engine_if_ready()
        .ok_or_else(|| "this Durable Object has no container".to_string())
        .and_then(|engine| {
            engine
                .with_legacy_cell(&cell, |handle| {
                    handle.address(port).map_err(anyhow::Error::msg)
                })
                .map_err(|error| format!("{error:#}"))
        });
    match address {
        Ok(address) => rv.set(v8::String::new(scope, &address).unwrap().into()),
        Err(message) => loader_throw(scope, &message),
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartArgs {
    entrypoint: Option<Vec<String>>,
    #[serde(default)]
    env: Vec<(String, String)>,
    #[serde(default)]
    enable_internet: bool,
    #[serde(default)]
    labels: Vec<(String, String)>,
}

pub(super) fn op_container_start(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let cell = string_arg(scope, &args, 0);
    let raw = string_arg(scope, &args, 1);
    let request: StartArgs = match serde_json::from_str(&raw) {
        Ok(request) => request,
        Err(error) => return loader_throw(scope, &format!("start(): {error}")),
    };
    if let Some(engine) = container::engine_if_ready() {
        if let Some(cell) = engine.cell(&cell) {
            if let Err(error) = engine.legacy_start_admission(&cell) {
                return loader_throw(scope, &format!("{error:#}"));
            }
        }
    }
    // The run opens here, on the calling thread, so the monitor() that
    // follows this call in the same turn waits for this start's exit.
    let run = container::engine_if_ready()
        .and_then(|engine| engine.cell(&cell))
        .map(|cell| cell.begin_run());
    let async_id = asyncrt::enqueue_io_context(async move {
        let (engine, cell) = cell_for(&cell).await?;
        let run = run.unwrap_or_else(|| cell.begin_run());
        engine
            .start(
                &cell,
                run,
                StartParams {
                    entrypoint: request.entrypoint,
                    env: request.env,
                    enable_internet: request.enable_internet,
                    labels: request.labels,
                },
            )
            .await
            .map_err(|error| format!("{error:#}"))?;
        Ok::<String, String>(String::new())
    });
    rv.set(promise_for(scope, async_id));
}

/// Resolves with the root process's exit code as text once the current
/// run ends. Unrefed: a handler can await it, but once the handler has
/// answered it cannot keep the event, and so the cell, alive. A drain
/// would otherwise wait on a promise that settles only when the container
/// exits. After the event, `running` reports the host's state.
pub(super) fn op_container_monitor(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let cell = string_arg(scope, &args, 0);
    let run = container::engine_if_ready()
        .and_then(|engine| engine.cell(&cell))
        .map_or(0, |cell| cell.current_run());
    let async_id = asyncrt::enqueue_unrefed(async move {
        let (engine, cell) = cell_for(&cell).await?;
        let code = engine.monitor(&cell, run).await?;
        Ok::<String, String>(code.to_string())
    });
    rv.set(promise_for(scope, async_id));
}

pub(super) fn op_container_destroy(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let cell = string_arg(scope, &args, 0);
    if let Some(engine) = container::engine_if_ready() {
        if let Some(handle) = engine.cell(&cell) {
            if let Err(error) = engine.refuse_native_legacy(&handle) {
                return loader_throw(scope, &format!("{error:#}"));
            }
        }
    }
    let async_id = asyncrt::enqueue(async move {
        let (engine, cell) = cell_for(&cell).await?;
        engine
            .destroy(&cell)
            .await
            .map_err(|error| format!("{error:#}"))?;
        Ok::<String, String>(String::new())
    });
    rv.set(promise_for(scope, async_id));
}

pub(super) struct AllocationBrand {
    token: String,
    generation: String,
}

fn bounded_string(
    scope: &mut v8::PinScope,
    value: v8::Local<v8::Value>,
    max: usize,
) -> Result<String, String> {
    let string = value
        .try_cast::<v8::String>()
        .map_err(|_| "allocation argument must be a string".to_string())?;
    if string.length() > max {
        return Err("allocation argument exceeds limit".to_string());
    }
    let text = string.to_rust_string_lossy(scope);
    if text.len() > max {
        return Err("allocation argument exceeds byte limit".to_string());
    }
    Ok(text)
}

fn allocation_event(
    scope: &mut v8::PinScope,
) -> Result<(Arc<ActorRuntimeState>, String, String), String> {
    let context = current_reaction_or_untracked_io_context(scope)
        .ok_or_else(|| "allocation continuation is retired".to_string())?;
    let event = current_cell_event(&context)
        .ok_or_else(|| "allocation requires an actor event".to_string())?;
    let table = context.native_upgrades();
    let runtime = actor_runtime_state(scope);
    if !table.generation().is_live()
        || !runtime
            .native_activations
            .authorises(&event.storage, &table)
    {
        return Err("allocation actor activation is not owned by this event".to_string());
    }
    let generation = table.generation().key().to_string();
    Ok((runtime, event.storage, generation))
}

fn allocation_scope_event(
    scope: &mut v8::PinScope,
    requested: &str,
) -> Result<(Arc<ActorRuntimeState>, String, String), String> {
    let event = allocation_event(scope)?;
    if event.1 != requested {
        return Err("allocation scope is not owned by this event".to_string());
    }
    Ok(event)
}

fn native_access_identity(
    scope: &mut v8::PinScope,
    requested: &str,
) -> Result<Option<Arc<ContainerEngine>>, String> {
    let Some(engine) = container::engine_if_ready() else {
        return Ok(None);
    };
    if !engine
        .native_scope(requested)
        .map_err(|_| "container ownership unavailable".to_string())?
    {
        return Ok(None);
    }
    allocation_scope_event(scope, requested)?;
    Ok(Some(engine))
}

pub(super) fn op_container_bind(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let result = (|| {
        let requested = bounded_string(scope, args.get(0), 4096)?;
        let (runtime, identity, generation) = allocation_scope_event(scope, &requested)?;
        let mut brands = runtime.allocation_brands.lock().unwrap();
        if brands
            .get(&identity)
            .is_none_or(|brand| brand.generation != generation)
        {
            let mut random = [0u8; 32];
            getrandom::fill(&mut random)
                .map_err(|_| "allocation authority unavailable".to_string())?;
            brands.insert(
                identity.clone(),
                AllocationBrand {
                    token: crate::engine_api::durable_object_id_hex(&random),
                    generation,
                },
            );
        }
        Ok::<_, String>(brands[&identity].token.clone())
    })();
    match result {
        Ok(token) => rv.set(v8::String::new(scope, &token).unwrap().into()),
        Err(_) if args.get(1).is_true() => {}
        Err(error) => loader_throw(scope, &error),
    }
}

pub(super) fn allocation_authority(
    scope: &mut v8::PinScope,
    token: v8::Local<v8::Value>,
) -> Result<String, String> {
    let token = bounded_string(scope, token, 64)?;
    let (runtime, identity, generation) = allocation_event(scope)?;
    let brands = runtime.allocation_brands.lock().unwrap();
    if !brands
        .get(&identity)
        .is_some_and(|brand| brand.token == token && brand.generation == generation)
    {
        return Err("allocation receiver or activation is invalid".to_string());
    }
    Ok(identity)
}

fn allocation_op(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
    operation: &str,
) {
    let identity = match allocation_authority(scope, args.get(0)) {
        Ok(identity) => identity,
        Err(error) => return loader_throw(scope, &error),
    };
    let raw = match bounded_string(
        scope,
        args.get(1),
        if operation == "start" { 65536 } else { 64 },
    ) {
        Ok(raw) => raw,
        Err(error) => return loader_throw(scope, &error),
    };
    let request = match operation {
        "start" => match serde_json::from_str::<AllocationOptions>(&raw) {
            Ok(options) => AllocationRequest::Start(options),
            Err(_) => return loader_throw(scope, "invalid allocation options"),
        },
        "destroy" => AllocationRequest::Destroy(raw),
        _ => AllocationRequest::Inspect(raw),
    };
    let Some(engine) = container::engine_if_ready() else {
        return loader_throw(scope, "allocation engine is not attached");
    };
    let Some(cell) = engine.cell(&identity) else {
        return loader_throw(scope, "this Durable Object has no container");
    };
    let epoch = storage::activation_epoch(&identity);
    #[cfg(all(debug_assertions, unix))]
    match crate::allocation_debug::capture_destroy(&engine, &cell, &identity, &request, epoch) {
        Ok(true) => return loader_throw(scope, "debug allocation destroy captured"),
        Ok(false) => {}
        Err(_) => return loader_throw(scope, "debug allocation control failed"),
    }
    let receiver = match engine.allocation_request_from_event(cell, request, epoch) {
        Ok(receiver) => receiver,
        Err(error) => return loader_throw(scope, &format!("{error:#}")),
    };
    // the receiver belongs to javascript, but the operation belongs to the engine.
    let async_id = asyncrt::enqueue_io_context(async move {
        let result = receiver
            .await
            .map_err(|_| "allocation owner stopped".to_string())?
            .map_err(|error| format!("{error:#}"))?;
        serde_json::to_string(&result)
            .map_err(|_| "allocation response encoding failed".to_string())
    });
    rv.set(promise_for(scope, async_id));
}

pub(super) fn op_container_start_allocation(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    rv: v8::ReturnValue<v8::Value>,
) {
    allocation_op(scope, args, rv, "start");
}

pub(super) fn op_container_inspect_allocation(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    rv: v8::ReturnValue<v8::Value>,
) {
    allocation_op(scope, args, rv, "inspect");
}

pub(super) fn op_container_destroy_allocation(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    rv: v8::ReturnValue<v8::Value>,
) {
    allocation_op(scope, args, rv, "destroy");
}

pub(super) fn op_container_signal(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let cell = string_arg(scope, &args, 0);
    let signal = number_arg(scope, &args, 1) as u32;
    if let Some(engine) = container::engine_if_ready() {
        if let Some(handle) = engine.cell(&cell) {
            if let Err(error) = engine.refuse_native_legacy(&handle) {
                return loader_throw(scope, &format!("{error:#}"));
            }
        }
    }
    let async_id = asyncrt::enqueue(async move {
        let (engine, cell) = cell_for(&cell).await?;
        engine
            .signal(&cell, signal)
            .await
            .map_err(|error| format!("{error:#}"))?;
        Ok::<String, String>(String::new())
    });
    rv.set(promise_for(scope, async_id));
}

pub(super) fn op_container_inactivity(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let cell = string_arg(scope, &args, 0);
    let duration = number_arg(scope, &args, 1);
    match native_access_identity(scope, &cell) {
        Err(error) => return loader_throw(scope, &error),
        Ok(Some(engine)) => {
            if let Err(error) = engine.with_allocation_event_cell(
                &cell,
                storage::activation_epoch(&cell),
                |handle| {
                    handle.set_inactivity(Duration::from_millis(duration));
                    Ok(())
                },
            ) {
                return loader_throw(scope, &format!("{error:#}"));
            }
            let async_id = asyncrt::enqueue(async { Ok::<String, String>(String::new()) });
            rv.set(promise_for(scope, async_id));
            return;
        }
        Ok(None) => {}
    }
    let async_id = asyncrt::enqueue(async move {
        let engine = container::engine()
            .await
            .map_err(|error| format!("{error:#}"))?;
        engine
            .with_legacy_cell(&cell, |handle| {
                handle.set_inactivity(Duration::from_millis(duration));
                Ok(())
            })
            .map_err(|error| format!("{error:#}"))?;
        Ok::<String, String>(String::new())
    });
    rv.set(promise_for(scope, async_id));
}

#[derive(serde::Deserialize)]
struct ExecArgs {
    cmd: Vec<String>,
    #[serde(default)]
    env: Vec<(String, String)>,
    cwd: Option<String>,
    user: Option<String>,
    #[serde(default)]
    combined: bool,
}

pub(super) fn op_container_exec(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let cell = string_arg(scope, &args, 0);
    let raw = string_arg(scope, &args, 1);
    let request: ExecArgs = match serde_json::from_str(&raw) {
        Ok(request) => request,
        Err(error) => return loader_throw(scope, &format!("exec(): {error}")),
    };
    let async_id = asyncrt::enqueue(async move {
        let (engine, cell) = cell_for(&cell).await?;
        let process = engine
            .exec(
                &cell,
                ExecParams {
                    cmd: request.cmd,
                    env: request.env,
                    cwd: request.cwd,
                    user: request.user,
                    combined: request.combined,
                },
            )
            .await
            .map_err(|error| format!("{error:#}"))?;
        Ok::<String, String>(
            serde_json::json!({ "id": process.id, "pid": process.pid }).to_string(),
        )
    });
    rv.set(promise_for(scope, async_id));
}

// The process ops below are unrefed like `monitor()`: a handler awaits
// them, and a process left running when the handler answers does not pin
// the cell.
fn process_arg(
    scope: &mut v8::PinScope,
    args: &v8::FunctionCallbackArguments,
) -> Result<Arc<container::ExecProcess>, String> {
    let id = number_arg(scope, args, 0);
    container::process(id).ok_or_else(|| "the process is closed".to_string())
}

/// One chunk of stdout (1) or stderr (2); an empty chunk is the end.
pub(super) fn op_container_exec_read(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let process = process_arg(scope, &args);
    let which = number_arg(scope, &args, 1) as u8;
    let async_id = asyncrt::enqueue_unrefed(async move {
        let process = process?;
        Ok::<Vec<u8>, String>(process.read(which).await.to_vec())
    });
    rv.set(promise_for(scope, async_id));
}

pub(super) fn op_container_exec_write(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let process = process_arg(scope, &args);
    let Some(bytes) = view_bytes(args.get(1)) else {
        return loader_throw(scope, "stdin write needs bytes");
    };
    let async_id = asyncrt::enqueue_unrefed(async move {
        process?.write(&bytes).await?;
        Ok::<String, String>(String::new())
    });
    rv.set(promise_for(scope, async_id));
}

pub(super) fn op_container_exec_close(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let process = process_arg(scope, &args);
    let async_id = asyncrt::enqueue_unrefed(async move {
        process?.close_stdin().await;
        Ok::<String, String>(String::new())
    });
    rv.set(promise_for(scope, async_id));
}

pub(super) fn op_container_exec_wait(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let process = process_arg(scope, &args);
    let async_id = asyncrt::enqueue_unrefed(async move {
        let code = process?
            .wait()
            .await
            .map_err(|error| format!("{error:#}"))?;
        Ok::<String, String>(code.to_string())
    });
    rv.set(promise_for(scope, async_id));
}

pub(super) fn op_container_exec_kill(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let process = process_arg(scope, &args);
    let signal = number_arg(scope, &args, 1) as u32;
    let async_id = asyncrt::enqueue_unrefed(async move {
        process?
            .kill(signal)
            .await
            .map_err(|error| format!("{error:#}"))?;
        Ok::<String, String>(String::new())
    });
    rv.set(promise_for(scope, async_id));
}

pub(super) fn op_container_exec_drop(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue<v8::Value>,
) {
    let id = number_arg(scope, &args, 0);
    container::drop_process(id);
}

#[cfg(all(test, not(celld_internal_tests)))]
#[path = "native_allocation_authority_tests.rs"]
mod native_allocation_authority_tests;
