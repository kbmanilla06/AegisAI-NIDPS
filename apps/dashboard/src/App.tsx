import { useEffect, useState } from "react";

type Health = { status: string; prevention_mode: string };

const apiBase = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

export function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    fetch(`${apiBase}/api/v1/health/live`, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error("Health request failed");
        setHealth((await response.json()) as Health);
      })
      .catch((requestError: unknown) => {
        if (requestError instanceof DOMException && requestError.name === "AbortError") return;
        setError(true);
      });
    return () => controller.abort();
  }, []);

  return (
    <main>
      <section aria-labelledby="title">
        <p className="eyebrow">Sprint 0 foundation</p>
        <h1 id="title">AegisAI NIDPS</h1>
        <p>Defensive network detection with prevention locked to simulation.</p>
        <div className="status" role="status" aria-live="polite">
          {health && (
            <>
              API: {health.status} · Prevention: {health.prevention_mode}
            </>
          )}
          {!health && !error && "Checking API health…"}
          {error && "API health is unavailable"}
        </div>
      </section>
    </main>
  );
}
