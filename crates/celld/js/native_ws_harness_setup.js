const __celld = {};
const __cell = { compat: {}, instances: {} };
const __ERROR_RESPONSE_MESSAGE = "network error";
const consumed = new Map();
const sent = [];
const closed = [];
const tracked = [];
const endings = new Map();
const generations = new Map([["actor-a", "generation-a"], ["", "worker-generation"]]);
const __ws_native_generation = (scope) => generations.get(scope);
const __ws_native_generation_live = (scope, key) => generations.get(scope) === key;
const microtasks = [];
let nextSocket = 1;
let actorScope = "actor-a";
const __currentActorScope = () => actorScope;
const __io_context_id = () => "native-ws-harness";
let refreshSignals = () => {};
const __rpcSignalRefresh = () => refreshSignals();
const setActorScope = (scope) => {
  actorScope = scope;
  __endActorEventsForContext(__io_context_id());
  if (scope) __beginActorEvent(scope);
};
const inputGates = new Map();
const closeInputGate = (scope) => {
  let started;
  const gate = { open: false, waiters: [], waited: new Promise((resolve) => { started = resolve; }) };
  gate.started = started;
  inputGates.set(scope, gate);
  return gate;
};
const openInputGate = (scope, failure) => {
  const gate = inputGates.get(scope);
  gate.open = true;
  for (const [resolve, reject] of gate.waiters.splice(0)) {
    if (failure) reject(failure);
    else resolve("");
  }
};
const __gate_is_open = (scope) => inputGates.get(scope)?.open !== false;
const __gate_wait = (scope, generation) => {
  if (!__ws_native_generation_live(scope, generation)) return Promise.reject(new Error("retired"));
  const gate = inputGates.get(scope);
  if (!gate || gate.open) return Promise.resolve("");
  gate.started();
  return new Promise((resolve, reject) => gate.waiters.push([resolve, reject]));
};
const until = async (predicate) => {
  for (let turn = 0; turn < 16; turn++) {
    if (predicate()) return;
    await Promise.resolve();
  }
  throw new Error("native callback did not settle within bounded microtasks");
};
const dialled = [];
const __ws_connect = (id, scope, url) => {
  dialled.push({id, scope, url});
  return Promise.resolve("");
};
class URL {
  constructor(value) { this.protocol = String(value).split(":")[0] + ":"; }
}
const __ws_alloc = () => nextSocket++;
const __ws_track_native = (id) => { tracked.push(id); return String(id); };
const __ws_drop_native_handle = () => {};
const __ws_consume_native = (id) => {
  consumed.set(id, (consumed.get(id) || 0) + 1);
  return [Promise.resolve(), new Promise((resolve) => endings.set(id, resolve))];
};
const __ws_send = (id, data) => sent.push([id, data]);
const __ws_send_binary = (id, data) => sent.push([id, Array.from(data)]);
const __ws_close = (id, code, reason) => closed.push([id, code, reason]);
const __registerWaitUntil = () => {};
const __ws_next = () => new Promise(() => {});
const queueMicrotask = (callback) => microtasks.push(callback);
class TextEncoder {
  encode(value) { return Uint8Array.from(String(value), (c) => c.charCodeAt(0)); }
}
class DOMException extends Error {}
class ErrorEvent {
  constructor(type, init) { return Object.assign(new Event(type), init); }
}
class Response {
  constructor(body, init = {}) {
    this.status = init.status ?? 200;
    this.webSocket = init.webSocket;
    this.headers = [];
    this._bodyBytes = new Uint8Array();
  }
}
const check = (condition, message) => { if (!condition) throw new Error(message); };
const throws = (operation, message) => {
  let thrown = false;
  try { operation(); } catch { thrown = true; }
  check(thrown, message);
};
