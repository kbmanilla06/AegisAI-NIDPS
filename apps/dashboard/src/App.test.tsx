import { render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { App } from "./App";

afterEach(() => vi.restoreAllMocks());

test("shows the simulation-only health state", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(JSON.stringify({ status: "ok", prevention_mode: "simulation" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );
  render(<App />);
  expect(await screen.findByText(/Prevention: simulation/)).toBeInTheDocument();
});
