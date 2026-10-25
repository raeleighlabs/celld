// the original consume control observes messages, then sends without accept.
const socket = __makeNativeSocket(__ws_alloc(), "probe.v1");
check(socket.readyState === WebSocket.OPEN, "fetch upgrade must already be open");
check(!consumed.has(socket._id), "returning a native handle must not consume it");
const observed = [];
socket.addEventListener("message", (event) => observed.push(event.data));
socket.addEventListener("error", () => { throw new Error("unexpected socket error"); });
socket._dispatchMessage("container-ready");
socket.send("consume-text");
socket._dispatchMessage("consume-text");
check(JSON.stringify(observed) === '["container-ready","consume-text"]', "implicit consumer lost messages");
check(consumed.get(socket._id) === 1, "observation and send must share one consumption");
check(sent[0][1] === "consume-text", "implicit consumer dropped send");
throws(() => __celld.__readResponse(new Response(null, {status: 101, webSocket: socket})), "consumed socket transferred");

const handler = __makeNativeSocket(__ws_alloc(), "");
const order = [];
handler.onmessage = () => order.push("handler");
handler.addEventListener("message", () => order.push("listener"));
handler.onmessage = () => order.push("replacement");
handler._dispatchMessage("payload");
check(JSON.stringify(order) === '["replacement","listener"]', "handler ordering changed");
check(consumed.get(handler._id) === 1, "handler assignment must consume once");

const direct = __makeNativeSocket(__ws_alloc(), "");
direct.send(new Uint8Array([0, 255]));
check(consumed.get(direct._id) === 1, "direct binary send must consume");
check(JSON.stringify(sent[1][1]) === '[0,255]', "binary send changed");
const closing = __makeNativeSocket(__ws_alloc(), "");
closing.close(1000, "done");
check(consumed.get(closing._id) === 1 && closed[0][2] === "done", "close must consume and close once");

const ignored = __makeNativeSocket(__ws_alloc(), "");
ignored.addEventListener("message", null);
ignored.addEventListener("message", () => {}, { signal: { aborted: true } });
check(!consumed.has(ignored._id), "ignored listener consumed transport");
const response = new Response(null, { status: 101, webSocket: ignored });
const extracted = __celld.__readResponse(response);
check(extracted.nativeSocketId === ignored._id, "native transport not extracted");
check(!extracted.workerSocketId && extracted.wsTargetJson === "null", "native socket became a pair or target");
throws(() => ignored.send("late"), "transferred socket sent");
throws(() => ignored.accept(), "transferred socket accepted");
throws(() => ignored.close(), "transferred socket closed");
throws(() => __celld.__readResponse(response), "native socket transferred twice");

const [client, server] = new WebSocketPair();
const pairMessages = [];
client.addEventListener("message", (event) => pairMessages.push(event.data));
check(!client._accepted && !server._accepted, "observation implicitly accepted pair");
client.accept();
server.accept();
server.send("pair-control");
while (microtasks.length) microtasks.shift()();
check(pairMessages[0] === "pair-control", "pair control failed");
check(!consumed.has(client._id), "pair entered native consumption path");

setActorScope("");
const worker = __makeNativeSocket(__ws_alloc(), "");
worker.send("worker-consumer");
check(worker._pumping && consumed.get(worker._id) === 1, "worker consumer did not start pull pump");
check(tracked.includes(worker._id), "native handle has no dropped-handle cleanup claim");

(async () => {
  setActorScope("actor-b");
  generations.set(actorScope, "generation-b");
  const live = __makeNativeSocket(__ws_alloc(), "");
  const notices = [];
  live.addEventListener("error", () => notices.push("error"));
  let reconnect;
  live.addEventListener("close", (event) => {
    notices.push(event.code);
    check(__currentActorScope() === "actor-b", "close listener lost its actor scope");
    reconnect = new WebSocket("ws://native-probe.invalid/reconnect");
  });
  const firstGate = closeInputGate("actor-b");
  let refreshes = 0;
  refreshSignals = () => refreshes++;
  endings.get(live._id)(JSON.stringify({code: 1006, reason: "origin revoked", clean: false}));
  setActorScope("");
  await firstGate.waited;
  check(notices.length === 0, "close listener bypassed input gate");
  openInputGate("actor-b");
  const secondGate = closeInputGate("actor-b");
  await secondGate.waited;
  check(notices.length === 0, "close listener missed gate reacquisition before delivery");
  check(refreshes === 0, "rpc signal callbacks bypassed a reacquired input gate");
  openInputGate("actor-b");
  await until(() => live.readyState === WebSocket.CLOSED);
  check(reconnect && !reconnect._polled && dialled.at(-1).scope === "actor-b", "reconnect was classified as a worker socket");
  check(__currentActorScope() === "", "notification leaked actor scope after delivery");
  check(JSON.stringify(notices) === '["error",1006]', "live consumer did not receive origin revocation");
  check(live.readyState === WebSocket.CLOSED && !__sockets.has(live._id), "live consumer remained rooted or open");
  refreshSignals = () => {};

  setActorScope("actor-b");
  const refreshHeld = __makeNativeSocket(__ws_alloc(), "");
  let refreshCallbacks = 0;
  refreshHeld.addEventListener("close", () => refreshCallbacks++);
  setActorScope("");
  let refreshGate;
  refreshSignals = () => {
    refreshSignals = () => {};
    refreshGate = closeInputGate("actor-b");
  };
  endings.get(refreshHeld._id)(JSON.stringify({code: 1000, reason: "refresh held gate", clean: true}));
  await until(() => refreshGate !== undefined);
  await refreshGate.waited;
  check(refreshCallbacks === 0, "signal refresh closed gate but close listener ran");
  check(__currentActorScope() === "", "notification kept actor scope while waiting again");
  openInputGate("actor-b");
  await until(() => refreshHeld.readyState === WebSocket.CLOSED);
  check(refreshCallbacks === 1, "notification did not resume after refresh gate opened");

  setActorScope("actor-b");
  const silent = __makeNativeSocket(__ws_alloc(), "");
  let silentCallbacks = 0;
  silent.addEventListener("error", () => silentCallbacks++);
  silent.addEventListener("close", () => silentCallbacks++);
  endings.get(silent._id)(JSON.stringify({code: 1006, reason: "consumer revoked", clean: false, notify: false}));
  await until(() => silent.readyState === WebSocket.CLOSED);
  check(silentCallbacks === 0 && !__sockets.has(silent._id), "consumer revocation notified or retained old socket");

  const retired = __makeNativeSocket(__ws_alloc(), "");
  let retiredCallbacks = 0;
  retired.addEventListener("error", () => retiredCallbacks++);
  retired.addEventListener("close", () => retiredCallbacks++);
  generations.set(actorScope, "replacement-b");
  __retireNativeGeneration(actorScope, "generation-b");
  const replacement = __makeNativeSocket(__ws_alloc(), "");
  replacement.addEventListener("message", () => {});
  endings.get(retired._id)(JSON.stringify({code: 1006, reason: "retired", clean: false}));
  await until(() => retired.readyState === WebSocket.CLOSED);
  check(retiredCallbacks === 0 && !__sockets.has(retired._id), "retired consumer ran callbacks or retained root");
  check(__sockets.has(replacement._id), "old notification removed successor socket");

  const clean = __makeNativeSocket(__ws_alloc(), "");
  const cleanNotices = [];
  clean.addEventListener("error", () => cleanNotices.push("error"));
  clean.addEventListener("close", (event) => cleanNotices.push([event.code, event.reason, event.wasClean]));
  endings.get(clean._id)(JSON.stringify({code: 1000, reason: "done", clean: true}));
  await until(() => clean.readyState === WebSocket.CLOSED);
  check(JSON.stringify(cleanNotices) === '[[1000,"done",true]]', "native close details changed");

  const stale = __makeNativeSocket(__ws_alloc(), "");
  let staleCallbacks = 0;
  stale.addEventListener("error", () => staleCallbacks++);
  stale.addEventListener("close", () => staleCallbacks++);
  const staleGate = closeInputGate("actor-b");
  endings.get(stale._id)(JSON.stringify({code: 1006, reason: "queued close", clean: false}));
  setActorScope("");
  await staleGate.waited;
  generations.set("actor-b", "successor-after-wait");
  openInputGate("actor-b");
  await until(() => stale.readyState === WebSocket.CLOSED);
  check(staleCallbacks === 0 && !__sockets.has(stale._id), "generation changed during gate wait but listener still ran");
  check(__currentActorScope() === "", "stale notification installed a successor actor frame");

  setActorScope("actor-b");
  const failed = __makeNativeSocket(__ws_alloc(), "");
  let failedCallbacks = 0;
  failed.addEventListener("close", () => failedCallbacks++);
  const failedGate = closeInputGate("actor-b");
  endings.get(failed._id)(JSON.stringify({code: 1000, reason: "pending close", clean: true}));
  setActorScope("");
  await failedGate.waited;
  openInputGate("actor-b", new Error("critical section failed"));
  await until(() => failed.readyState === WebSocket.CLOSED);
  check(failedCallbacks === 0 && !__sockets.has(failed._id), "failed gate delivered close listener");

  setActorScope("actor-b");
  const refreshRetired = __makeNativeSocket(__ws_alloc(), "");
  let refreshRetiredCallbacks = 0;
  refreshRetired.addEventListener("close", () => refreshRetiredCallbacks++);
  setActorScope("");
  refreshSignals = () => {
    refreshSignals = () => {};
    generations.set("actor-b", "retired-during-refresh");
  };
  endings.get(refreshRetired._id)(JSON.stringify({code: 1000, reason: "refresh retired owner", clean: true}));
  await until(() => refreshRetired.readyState === WebSocket.CLOSED);
  check(refreshRetiredCallbacks === 0 && !__sockets.has(refreshRetired._id), "signal refresh retired owner but close listener ran");
  check(__currentActorScope() === "", "retired notification leaked actor scope");
})();
