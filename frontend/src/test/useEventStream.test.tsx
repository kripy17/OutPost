// useEventStream (lib/useEventStream.ts) — the hook wrapper over the shared
// SSE hub. Tests with renderHook + a fake EventSource: mount subscribes and
// delivers parsed alert payloads, the ref pattern always calls the LATEST
// callback across re-renders, and unmount unsubscribes (closing the shared
// stream when it was the last subscriber).

import { renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { StreamAlert } from "../lib/useEventStream";

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

describe("useEventStream", () => {
  it("subscribes on mount, delivers alert payloads, and unsubscribes on unmount", async () => {
    const { useEventStream } = await import("../lib/useEventStream");
    const alerts: StreamAlert[] = [];
    const { unmount } = renderHook(() => useEventStream((a) => alerts.push(a)));
    expect(FakeEventSource.instances.length).toBe(1);
    FakeEventSource.instances[0].fire("alert", { rule_id: "r1", severity: "malicious" });
    expect(alerts).toHaveLength(1);
    expect(alerts[0].rule_id).toBe("r1");
    unmount();
    expect(FakeEventSource.instances[0].closed).toBe(true);
  });

  it("always uses the latest callback across re-renders (ref pattern)", async () => {
    const { useEventStream } = await import("../lib/useEventStream");
    const calls: string[] = [];
    const { rerender } = renderHook(({ cb }: { cb: (a: StreamAlert) => void }) => useEventStream(cb), {
      initialProps: { cb: () => calls.push("first") },
    });
    rerender({ cb: () => calls.push("second") });
    FakeEventSource.instances[0].fire("alert", { rule_id: "x", severity: "suspicious" });
    expect(calls).toEqual(["second"]);
  });
});
