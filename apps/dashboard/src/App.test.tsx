import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { App } from "./App";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  localStorage.clear();
});

class TestWebSocket {
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;

  constructor(url: string) {
    void url;
    queueMicrotask(() => this.onopen?.());
  }

  close() {
    this.onclose?.();
  }
}

test("shows the simulation-only health state", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(new Response(JSON.stringify({ status: "ok", prevention_mode: "simulation" }), { status: 200 }))
    .mockResolvedValueOnce(new Response(null, { status: 401 }));
  render(<App />);
  expect(await screen.findByText(/Prevention: simulation/)).toBeInTheDocument();
});

test("signs in without placing credentials in browser storage", async () => {
  const fetchMock = vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(new Response(JSON.stringify({ status: "ok", prevention_mode: "simulation" }), { status: 200 }))
    .mockResolvedValueOnce(new Response(null, { status: 401 }))
    .mockResolvedValueOnce(new Response(JSON.stringify({
      user: { id: "u1", email: "admin@example.com", roles: ["System Administrator"], is_active: true, version: 1 },
      permissions: [], csrf_token: "csrf-only-in-memory",
    }), { status: 200 }));
  render(<App />);
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: "admin@example.com" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "long-enough-password" } });
  fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
  expect(await screen.findByText("admin@example.com")).toBeInTheDocument();
  const loginRequest = fetchMock.mock.calls[2]?.[1];
  expect(loginRequest).toMatchObject({ credentials: "include", method: "POST" });
  expect(localStorage.length).toBe(0);
});

test("submits controlled telemetry as multipart without trusting a browser MIME", async () => {
  const auth = {
    user: { id: "u1", email: "admin@example.com", roles: ["Security Administrator"], is_active: true, version: 1 },
    permissions: ["telemetry:read", "ingestion:submit"],
  };
  const fetchMock = vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(new Response(JSON.stringify({ status: "ok", prevention_mode: "simulation" }), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify(auth), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify({ csrf_token: "csrf-memory-only" }), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify([]), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify({
      id: "job-1",
      source_type: "normalized",
      status: "pending",
      accepted_records: 0,
      rejected_records: 0,
      duplicate_records: 0,
      error_code: null,
      created_at: "2026-07-14T00:00:00Z",
    }), { status: 202 }));
  render(<App />);
  expect(await screen.findByText("Telemetry ingestion")).toBeInTheDocument();
  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(4));
  const file = new File(['{"schema_version":"1"}\n'], "untrusted-name.jsonl", {
    type: "application/octet-stream",
  });
  fireEvent.change(screen.getByLabelText("Controlled telemetry file"), {
    target: { files: [file] },
  });
  const submit = screen.getByRole("button", { name: "Submit telemetry" });
  fireEvent.submit(submit.closest("form") as HTMLFormElement);
  expect(await screen.findByText(/normalized · pending/)).toBeInTheDocument();
  const request = fetchMock.mock.calls[4]?.[1];
  expect(request?.body).toBeInstanceOf(FormData);
  expect(new Headers(request?.headers).has("Content-Type")).toBe(false);
});

test("shows versioned deterministic rules and alerts with bounded live status", async () => {
  vi.stubGlobal("WebSocket", TestWebSocket);
  const auth = {
    user: { id: "u1", email: "viewer@example.com", roles: ["Viewer"], is_active: true, version: 1 },
    permissions: ["rules:read", "alerts:read"],
  };
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(new Response(JSON.stringify({ status: "ok", prevention_mode: "simulation" }), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify(auth), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify({ csrf_token: "csrf-memory-only" }), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify([{
      id: "rule-1", rule_key: "behavior.port_scan", version: 1, name: "Port scan indicator",
      description: "Deterministic scan condition", category: "reconnaissance", evaluator_key: "port_scan_v1",
      parameters: { threshold: 20 }, window_seconds: 60, severity: "medium",
      false_positive_guidance: "Authorized scanners", investigation_guidance: "Confirm authorization",
      prevention_recommendation: "Review only", lifecycle_state: "approved", is_active: true,
    }]), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify([{
      id: "alert-1", source_type: "behavioral_rule", category: "reconnaissance", severity: "medium",
      status: "new", grouping: {}, occurrence_count: 2, first_seen: "2026-07-14T00:00:00Z",
      last_seen: "2026-07-14T00:01:00Z",
    }]), { status: 200 }));
  render(<App />);
  expect(await screen.findByText(/Port scan indicator/)).toBeInTheDocument();
  expect(await screen.findByText(/reconnaissance · behavioral_rule · occurrences 2/)).toBeInTheDocument();
  expect(await screen.findByText("Live updates: connected")).toBeInTheDocument();
  expect(screen.getByText(/Rules never invoke prevention/)).toBeInTheDocument();
});

test("shows feature and dataset governance metadata without raw rows or vectors", async () => {
  const auth = {
    user: { id: "u1", email: "analyst@example.com", roles: ["Senior Analyst"], is_active: true, version: 1 },
    permissions: ["features:read", "datasets:read"],
  };
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(new Response(JSON.stringify({ status: "ok", prevention_mode: "simulation" }), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify(auth), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify({ csrf_token: "csrf-memory-only" }), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify([{
      id: "schema-1", name: "flow_features", version: "1.0.0", definition_hash: "a".repeat(64),
      lifecycle_state: "approved", ordered_definition: {
        windows: [{ seconds: 60 }, { seconds: 300 }],
        features: [{ name: "duration_ms", dtype: "int64", unit: "milliseconds", missing_policy: "required" }],
      },
    }]), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify([]), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify([{
      id: "dataset-1", name: "UNSW-NB15", version: "official-source-review-2026-07-14",
      publisher: "UNSW Canberra at ADFA", status: "proposed", citation_required: true,
      commercial_approval_required: true, acquisition_authorized: false,
    }]), { status: 200 }));
  render(<App />);
  expect(await screen.findByText("Feature engineering")).toBeInTheDocument();
  expect(await screen.findByText(/UNSW-NB15.*acquisition not authorized/)).toBeInTheDocument();
  expect(screen.getByText(/Raw endpoints, vectors, paths, labels/)).toBeInTheDocument();
  expect(screen.queryByText("192.0.2.10")).not.toBeInTheDocument();
});
