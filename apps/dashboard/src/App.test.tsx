import { cleanup, fireEvent, render, screen } from "@testing-library/react";
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
