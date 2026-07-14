import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { App } from "./App";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  localStorage.clear();
});

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
