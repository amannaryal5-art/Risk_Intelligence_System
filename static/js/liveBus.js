import { emit } from "./utils.js";

export class LiveDataBus {
  constructor({ wsPath = "/ws/live", ssePath = "/api/v1/ioc/stream" } = {}) {
    this.wsPath = wsPath;
    this.ssePath = ssePath;
    this.ws = null;
    this.sse = null;
    this.subscribers = {};
    this.reconnectAttempts = 0;
    this.heartbeatTimer = 0;
    this.pongTimer = 0;
    this.actionQueue = [];
    this.connected = false;
    this.paused = false;
    this.latencyReadings = [];
  }

  connect() {
    this.connectWebSocket();
    this.connectSse();
  }

  connectWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    this.publish("connection", { state: "reconnecting", retryIn: this.backoff() / 1000 });
    try {
      this.ws = new WebSocket(`${protocol}//${window.location.host}${this.wsPath}`);
    } catch {
      this.scheduleReconnect();
      return;
    }
    this.ws.addEventListener("open", () => {
      this.connected = true;
      this.reconnectAttempts = 0;
      this.publish("connection", { state: "live" });
      this.startHeartbeat();
      this.flushQueue();
    });
    this.ws.addEventListener("message", (event) => {
      this.handleMessage(event.data);
    });
    this.ws.addEventListener("close", () => {
      this.connected = false;
      this.publish("connection", { state: "offline", queued: this.actionQueue.length });
      this.scheduleReconnect();
    });
    this.ws.addEventListener("error", () => {
      this.connected = false;
      this.publish("connection", { state: "offline", queued: this.actionQueue.length });
    });
  }

  connectSse() {
    if (!("EventSource" in window)) return;
    this.sse?.close();
    this.sse = new EventSource(this.ssePath, { withCredentials: true });
    this.sse.addEventListener("message", (event) => {
      if (this.paused) return;
      try {
        const payload = JSON.parse(event.data);
        this.publish("ioc", payload);
      } catch {
        this.publish("ioc", { raw: event.data });
      }
    });
    this.sse.addEventListener("error", () => {
      this.publish("stream:error", { source: "ioc" });
    });
  }

  handleMessage(raw) {
    let payload = raw;
    try {
      payload = JSON.parse(raw);
    } catch {
      // keep raw payload
    }
    if (payload?.type === "pong") {
      const started = Number(payload.ts || Date.now());
      this.recordLatency(Math.max(1, Date.now() - started));
      window.clearTimeout(this.pongTimer);
      return;
    }
    if (payload?.type) this.publish(payload.type, payload);
    this.publish("ws:message", payload);
    if (payload?.severity === "critical") {
      emit("alert:critical", payload);
    }
  }

  startHeartbeat() {
    window.clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = window.setInterval(() => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
      const ts = Date.now();
      this.ws.send(JSON.stringify({ type: "ping", ts }));
      this.pongTimer = window.setTimeout(() => {
        this.ws?.close();
      }, 10000);
    }, 30000);
  }

  recordLatency(value) {
    this.latencyReadings.push(value);
    this.latencyReadings = this.latencyReadings.slice(-10);
    this.publish("latency", { current: value, values: [...this.latencyReadings] });
  }

  scheduleReconnect() {
    const delay = this.backoff();
    this.publish("connection", { state: "reconnecting", retryIn: delay / 1000, queued: this.actionQueue.length });
    window.setTimeout(() => this.connectWebSocket(), delay);
  }

  backoff() {
    const delay = Math.min(30000, 1000 * (2 ** this.reconnectAttempts));
    this.reconnectAttempts += 1;
    return delay;
  }

  subscribe(event, callback) {
    this.subscribers[event] = this.subscribers[event] || new Set();
    this.subscribers[event].add(callback);
    return () => this.unsubscribe(event, callback);
  }

  unsubscribe(event, callback) {
    this.subscribers[event]?.delete(callback);
  }

  publish(event, data) {
    this.subscribers[event]?.forEach((callback) => callback(data));
  }

  enqueueAction(action) {
    this.actionQueue.push(action);
    this.publish("queue:changed", { count: this.actionQueue.length });
  }

  async flushQueue() {
    const queued = [...this.actionQueue];
    this.actionQueue = [];
    this.publish("queue:changed", { count: 0 });
    for (const action of queued) {
      await action();
    }
  }

  togglePause() {
    this.paused = !this.paused;
    this.publish("stream:paused", { paused: this.paused });
    return this.paused;
  }
}
