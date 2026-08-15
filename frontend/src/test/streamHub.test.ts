// streamHub (lib/streamHub.ts) — the app's ONE shared EventSource, fanned out
// to subscribers. Tests drive a fake EventSource: URL construction (tokenless
// vs ?token=), fan-out to matching handlers only, tolerance of malformed
// frames, closing only when the last subscriber leaves (and reopening on
// demand), and graceful degradation when EventSource is unavailable.
//
// The hub holds module-scope state (es + subs), so each test resets modules
// and imports fresh — the standard pattern for module-singleton testing.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  url: string;
  closed = false;
  private listeners = new Map<string, (e: MessageEvent) => void>();
  constructor(url: string) {
    this.url = url;
    FakeEventSource.instances.push(this);
  }
  addEventListener(name: string, fn: (e: MessageEvent) => void) {
    this.listeners.set(name, fn);
  }
  close() {
    this.closed = true;
  }
  fire(name: string, data: unknown) {
    this.listeners.get(name)?.({ data: JSON.stringify(data) } as MessageEvent);
  }
  fireRaw(name: string, raw: string) {
    this.listeners.get(name)?.({ data: raw } as MessageEvent);
  }
}

beforeEach(() => {
  vi.resetModules();
  FakeEventSource.instances = [];
  vi.stubGlobal("EventSource", FakeEventSource);
  localStorage.removeItem("outpost-token");
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("streamHub", () => {
  async function hub() {
    return await import("../lib/streamHub");
  }

  it("opens a tokenless stream URL when no auth token is set", async () => {
    const { subscribeStream } = await hub();
    const unsub = subscribeStream({ onAlert: () => {} });
    expect(FakeEventSource.instances.length).toBe(1);
    expect(FakeEventSource.instances[0].url).toMatch(/\/events\/stream$/);
    expect(FakeEventSource.instances[0].url).not.toContain("token=");
    unsub();
  });

  it("appends ?token= when an auth token exists", async () => {
    localStorage.setItem("outpost-token", "sekret");
    const { subscribeStream } = await hub();
    const unsub = subscribeStream({});
    expect(FakeEventSource.instances[0].url).toMatch(/\/events\/stream\?token=sekret$/);
    unsub();
  });

  it("fans out parsed payloads only to matching handlers", async () => {
    const { subscribeStream } = await hub();
    const alerts: { rule_id: string }[] = [];
    const runUpdates: unknown[] = [];
    subscribeStream({ onAlert: (a) => alerts.push(a) });
    subscribeStream({ onRunUpdate: (r) => runUpdates.push(r) });
    const es = FakeEventSource.instances[0];
    es.fire("alert", { rule_id: "r1", severity: "malicious" });
    es.fire("run-update", { run_id: "x", events: 3 });
    es.fire("alert", { rule_id: "r2", severity: "suspicious" });
    expect(alerts.map((a) => a.rule_id)).toEqual(["r1", "r2"]);
    expect(runUpdates).toEqual([{ run_id: "x", events: 3 }]);
  });

  it("ignores malformed frames without killing the stream", async () => {
    const { subscribeStream } = await hub();
    const alerts: { rule_id: string }[] = [];
    subscribeStream({ onAlert: (a) => alerts.push(a) });
    const es = FakeEventSource.instances[0];
    es.fireRaw("alert", "not-json{");
    es.fire("alert", { rule_id: "ok", severity: "malicious" });
    expect(alerts).toHaveLength(1);
    expect(alerts[0].rule_id).toBe("ok");
  });

  it("keeps the stream open until the last subscriber leaves, then reopens on demand", async () => {
    const { subscribeStream } = await hub();
    const a = subscribeStream({ onAlert: () => {} });
    const b = subscribeStream({ onRunUpdate: () => {} });
    a();
    expect(FakeEventSource.instances[0].closed).toBe(false);
    b();
    expect(FakeEventSource.instances[0].closed).toBe(true);
    subscribeStream({});
    expect(FakeEventSource.instances.length).toBe(2); // reopened for a new subscriber
  });

  it("degrades gracefully when EventSource is unavailable", async () => {
    vi.stubGlobal(
      "EventSource",
      class {
        constructor() {
          throw new Error("no SSE");
        }
      },
    );
    const { subscribeStream } = await hub();
    const unsub = subscribeStream({ onAlert: () => {} });
    expect(FakeEventSource.instances.length).toBe(0);
    expect(typeof unsub).toBe("function");
    unsub(); // must not throw
  });
});
