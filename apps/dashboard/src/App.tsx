import { FormEvent, useEffect, useState } from "react";
import { apiRequest } from "./api";

type Health = { status: string; prevention_mode: string };
type User = { id: string; email: string; roles: string[]; is_active: boolean; version: number };
type Auth = { user: User; permissions: string[]; csrf_token?: string };
type Asset = {
  id: string;
  name: string;
  network_zone: string;
  criticality: string;
  is_active: boolean;
};
type Sensor = {
  id: string;
  name: string;
  sensor_type: string;
  status: string;
  credential_version: number;
};

export function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [auth, setAuth] = useState<Auth | null>(null);
  const [csrfToken, setCsrfToken] = useState("");
  const [error, setError] = useState("");
  const [assets, setAssets] = useState<Asset[]>([]);
  const [sensors, setSensors] = useState<Sensor[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [issuedCredential, setIssuedCredential] = useState("");

  const can = (permission: string) => auth?.permissions.includes(permission) ?? false;

  useEffect(() => {
    void apiRequest<Health>("/health/live")
      .then(setHealth)
      .catch(() => setError("API health is unavailable"));
    void apiRequest<Auth>("/auth/me")
      .then(async (current) => {
        const csrf = await apiRequest<{ csrf_token: string }>("/auth/csrf");
        setAuth(current);
        setCsrfToken(csrf.csrf_token);
      })
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!auth) return;
    if (auth.permissions.includes("assets:read")) void apiRequest<Asset[]>("/assets").then(setAssets);
    if (auth.permissions.includes("sensors:read")) void apiRequest<Sensor[]>("/sensors").then(setSensors);
    if (auth.permissions.includes("users:read")) void apiRequest<User[]>("/users").then(setUsers);
  }, [auth]);

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const data = new FormData(event.currentTarget);
    try {
      const result = await apiRequest<Auth>("/auth/login", {
        method: "POST",
        body: JSON.stringify({ email: data.get("email"), password: data.get("password") }),
      });
      setAuth(result);
      setCsrfToken(result.csrf_token ?? "");
      event.currentTarget.reset();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Login failed");
    }
  }

  async function logout() {
    await apiRequest<void>("/auth/logout", { method: "POST", csrfToken });
    setAuth(null);
    setCsrfToken("");
    setAssets([]);
    setSensors([]);
    setUsers([]);
    setIssuedCredential("");
  }

  async function createAsset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const asset = await apiRequest<Asset>("/assets", {
      method: "POST",
      csrfToken,
      body: JSON.stringify({
        name: data.get("name"),
        network_zone: data.get("network_zone"),
        criticality: data.get("criticality"),
        is_internal: true,
      }),
    });
    setAssets((current) => [...current, asset]);
    form.reset();
  }

  async function createSensor(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const result = await apiRequest<{ sensor: Sensor; credential: string }>("/sensors", {
      method: "POST",
      csrfToken,
      body: JSON.stringify({ name: data.get("name"), sensor_type: data.get("sensor_type") }),
    });
    setSensors((current) => [...current, result.sensor]);
    setIssuedCredential(result.credential);
    form.reset();
  }

  async function createUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const user = await apiRequest<User>("/users", {
      method: "POST",
      csrfToken,
      body: JSON.stringify({
        email: data.get("email"),
        password: data.get("password"),
        roles: [data.get("role")],
      }),
    });
    setUsers((current) => [...current, user]);
    form.reset();
  }

  return (
    <main>
      <header>
        <div>
          <p className="eyebrow">Sprint 1 secure platform shell</p>
          <h1>AegisAI NIDPS</h1>
        </div>
        <div className="status" role="status" aria-live="polite">
          {health ? `API: ${health.status} · Prevention: ${health.prevention_mode}` : "Checking API…"}
        </div>
      </header>

      {!auth ? (
        <section className="panel login" aria-labelledby="login-title">
          <h2 id="login-title">Sign in</h2>
          <p>Use an administrator-created account. Credentials are never stored in browser storage.</p>
          <form onSubmit={(event) => void login(event)}>
            <label>Email<input name="email" type="email" autoComplete="username" required /></label>
            <label>Password<input name="password" type="password" autoComplete="current-password" required /></label>
            <button type="submit">Sign in</button>
          </form>
          {error && <p className="error" role="alert">{error}</p>}
        </section>
      ) : (
        <>
          <section className="panel identity" aria-labelledby="identity-title">
            <div>
              <h2 id="identity-title">{auth.user.email}</h2>
              <p>{auth.user.roles.join(" · ")}</p>
            </div>
            <button className="secondary" onClick={() => void logout()}>Sign out</button>
          </section>

          <div className="grid">
            {can("assets:read") && (
              <section className="panel">
                <h2>Assets</h2>
                <ul>{assets.map((asset) => <li key={asset.id}>{asset.name} · {asset.criticality} · {asset.network_zone}</li>)}</ul>
                {can("assets:manage") && <form onSubmit={(event) => void createAsset(event)}>
                  <label>Name<input name="name" required maxLength={128} /></label>
                  <label>Network zone<input name="network_zone" required pattern="[A-Za-z0-9_.-]+" /></label>
                  <label>Criticality<select name="criticality" defaultValue="medium"><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label>
                  <button type="submit">Register asset</button>
                </form>}
              </section>
            )}

            {can("sensors:read") && (
              <section className="panel">
                <h2>Sensors</h2>
                <ul>{sensors.map((sensor) => <li key={sensor.id}>{sensor.name} · {sensor.sensor_type} · {sensor.status}</li>)}</ul>
                {issuedCredential && <div className="credential" role="alert"><strong>Copy this credential now.</strong><code>{issuedCredential}</code><button className="secondary" onClick={() => setIssuedCredential("")}>Clear</button></div>}
                {can("sensors:manage") && <form onSubmit={(event) => void createSensor(event)}>
                  <label>Name<input name="name" required maxLength={128} /></label>
                  <label>Type<select name="sensor_type" defaultValue="flow"><option>flow</option><option>zeek</option><option>suricata</option></select></label>
                  <button type="submit">Register sensor</button>
                </form>}
              </section>
            )}

            {can("users:read") && (
              <section className="panel">
                <h2>Users</h2>
                <ul>{users.map((user) => <li key={user.id}>{user.email} · {user.roles.join(", ")}</li>)}</ul>
                {can("users:manage") && <form onSubmit={(event) => void createUser(event)}>
                  <label>Email<input name="email" type="email" required /></label>
                  <label>Temporary password<input name="password" type="password" minLength={12} maxLength={128} required /></label>
                  <label>Role<select name="role" defaultValue="Viewer"><option>Viewer</option><option>SOC Analyst</option><option>Senior Analyst</option><option>Security Administrator</option><option>System Administrator</option><option>Auditor</option></select></label>
                  <button type="submit">Create user</button>
                </form>}
              </section>
            )}
          </div>
        </>
      )}
    </main>
  );
}
