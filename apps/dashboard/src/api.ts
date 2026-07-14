export const apiBase = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

type RequestOptions = RequestInit & { csrfToken?: string };

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
  if (options.csrfToken) headers.set("X-CSRF-Token", options.csrfToken);
  const response = await fetch(`${apiBase}/api/v1${path}`, {
    ...options,
    headers,
    credentials: "include",
  });
  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { message?: string } | null;
    throw new Error(payload?.message ?? "Request failed");
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}
