import { FormEvent, useEffect, useState } from "react";
import { apiBase, apiRequest } from "./api";

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
type IngestionJob = {
  id: string;
  source_type: string;
  status: string;
  accepted_records: number;
  rejected_records: number;
  duplicate_records: number;
  error_code: string | null;
  created_at: string;
};
type RuleVersion = {
  id: string;
  rule_key: string;
  version: number;
  name: string;
  description: string;
  category: string;
  evaluator_key: string;
  parameters: Record<string, unknown>;
  window_seconds: number;
  severity: string;
  false_positive_guidance: string;
  investigation_guidance: string;
  prevention_recommendation: string;
  lifecycle_state: string;
  is_active: boolean;
};
type Alert = {
  id: string;
  source_type: string;
  category: string;
  severity: string;
  status: string;
  grouping: Record<string, unknown>;
  occurrence_count: number;
  first_seen: string;
  last_seen: string;
};
type FeatureDefinition = { name: string; dtype: string; unit: string; missing_policy: string };
type FeatureSchema = {
  id: string;
  name: string;
  version: string;
  definition_hash: string;
  lifecycle_state: string;
  ordered_definition: { features?: FeatureDefinition[]; windows?: { seconds: number }[] };
};
type FeatureJob = {
  id: string;
  feature_schema_id: string;
  ingestion_job_id: string;
  status: string;
  input_count: number;
  output_count: number;
  error_code: string | null;
  artifact: { sha256: string; row_count: number; expires_at: string } | null;
};
type DatasetVersion = {
  id: string;
  name: string;
  version: string;
  publisher: string;
  status: string;
  citation_required: boolean;
  commercial_approval_required: boolean;
  acquisition_authorized: boolean;
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
  const [ingestionJobs, setIngestionJobs] = useState<IngestionJob[]>([]);
  const [rules, setRules] = useState<RuleVersion[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [liveAlerts, setLiveAlerts] = useState(false);
  const [featureSchemas, setFeatureSchemas] = useState<FeatureSchema[]>([]);
  const [featureJobs, setFeatureJobs] = useState<FeatureJob[]>([]);
  const [datasets, setDatasets] = useState<DatasetVersion[]>([]);

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
    if (auth.permissions.includes("telemetry:read")) {
      void apiRequest<IngestionJob[]>("/ingestion/jobs").then(setIngestionJobs);
    }
    if (auth.permissions.includes("rules:read")) {
      void apiRequest<RuleVersion[]>("/rules").then(setRules);
    }
    if (auth.permissions.includes("features:read")) {
      void apiRequest<FeatureSchema[]>("/feature-schemas").then(setFeatureSchemas);
      void apiRequest<FeatureJob[]>("/feature-jobs").then(setFeatureJobs);
    }
    if (auth.permissions.includes("datasets:read")) {
      void apiRequest<DatasetVersion[]>("/datasets").then(setDatasets);
    }
    if (auth.permissions.includes("alerts:read")) {
      const refresh = () => void apiRequest<Alert[]>("/alerts").then(setAlerts);
      refresh();
      const timer = window.setInterval(refresh, 30_000);
      const socket = new WebSocket(`${apiBase.replace(/^http/, "ws")}/ws/v1/alerts`);
      socket.onopen = () => setLiveAlerts(true);
      socket.onmessage = (event) => {
        const message = JSON.parse(String(event.data)) as { event?: string };
        if (message.event === "alert_changed") refresh();
      };
      socket.onerror = () => setLiveAlerts(false);
      socket.onclose = () => setLiveAlerts(false);
      return () => {
        window.clearInterval(timer);
        socket.close();
      };
    }
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
    setIngestionJobs([]);
    setRules([]);
    setAlerts([]);
    setLiveAlerts(false);
    setFeatureSchemas([]);
    setFeatureJobs([]);
    setDatasets([]);
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

  async function submitTelemetry(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const form = event.currentTarget;
    const data = new FormData(form);
    try {
      const job = await apiRequest<IngestionJob>("/ingestion/jobs", {
        method: "POST",
        csrfToken,
        body: data,
      });
      setIngestionJobs((current) => [job, ...current]);
      form.reset();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Upload failed");
    }
  }

  async function createRuleDraft(event: FormEvent<HTMLFormElement>, current: RuleVersion) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const threshold = Number(data.get("threshold"));
    const draft = await apiRequest<RuleVersion>(`/rules/${current.rule_key}/versions`, {
      method: "POST",
      csrfToken,
      body: JSON.stringify({
        name: current.name,
        description: current.description,
        category: current.category,
        evaluator_key: current.evaluator_key,
        parameters: { ...current.parameters, threshold },
        window_seconds: current.window_seconds,
        severity: current.severity,
        mitre_mappings: [],
        false_positive_guidance: current.false_positive_guidance,
        investigation_guidance: current.investigation_guidance,
        prevention_recommendation: current.prevention_recommendation,
        change_rationale: "Administrator-created threshold draft for reviewed regression testing.",
      }),
    });
    setRules((items) => [draft, ...items]);
    form.reset();
  }

  async function reviewRule(rule: RuleVersion) {
    const reviewed = await apiRequest<RuleVersion>(`/rule-versions/${rule.id}/review`, {
      method: "POST",
      csrfToken,
      body: JSON.stringify({
        approved: true,
        reason: "Administrator confirms deterministic regression evidence was reviewed.",
        regression_evidence: "local-sprint3-regression-suite",
      }),
    });
    setRules((items) => items.map((item) => item.id === reviewed.id ? reviewed : item));
  }

  async function activateRule(rule: RuleVersion) {
    const current = rules.find((item) => item.rule_key === rule.rule_key && item.is_active);
    const activated = await apiRequest<RuleVersion>(`/rule-versions/${rule.id}/activate`, {
      method: "POST",
      csrfToken,
      body: JSON.stringify({
        reason: "Activate the approved deterministic rule version.",
        regression_evidence: "local-sprint3-regression-suite",
        expected_active_version_id: current?.id ?? null,
      }),
    });
    setRules((items) => items.map((item) => item.rule_key === activated.rule_key
      ? { ...item, is_active: item.id === activated.id }
      : item));
  }

  async function materializeFeatures(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const job = await apiRequest<FeatureJob>("/feature-jobs", {
      method: "POST",
      csrfToken,
      headers: { "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({
        feature_schema_id: data.get("feature_schema_id"),
        ingestion_job_id: data.get("ingestion_job_id"),
        requested_limit: 10000,
      }),
    });
    setFeatureJobs((current) => [job, ...current]);
    form.reset();
  }

  return (
    <main>
      <header>
        <div>
          <p className="eyebrow">Sprint 4 versioned feature pipeline</p>
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
          {error && <p className="error" role="alert">{error}</p>}

          <div className="grid">
            {can("features:read") && (
              <section className="panel">
                <h2>Feature engineering</h2>
                <p>Metadata-only view. Raw endpoints, vectors, paths, labels, and dataset rows are never displayed.</p>
                {featureSchemas.map((schema) => (
                  <details key={schema.id}>
                    <summary>{schema.name} v{schema.version} · {schema.lifecycle_state}</summary>
                    <p>Windows: {(schema.ordered_definition.windows ?? []).map((window) => `${window.seconds}s`).join(", ")}</p>
                    <ul>
                      {(schema.ordered_definition.features ?? []).map((feature) => (
                        <li key={feature.name}>{feature.name} · {feature.dtype} · {feature.unit} · {feature.missing_policy}</li>
                      ))}
                    </ul>
                  </details>
                ))}
                <ul>
                  {featureJobs.map((job) => (
                    <li key={job.id}>
                      {job.status} · rows {job.output_count}
                      {job.artifact ? ` · SHA-256 ${job.artifact.sha256.slice(0, 12)}… · expires ${new Date(job.artifact.expires_at).toLocaleDateString()}` : ""}
                      {job.error_code ? ` · ${job.error_code}` : ""}
                    </li>
                  ))}
                </ul>
                {can("features:materialize") && featureSchemas.length > 0 && ingestionJobs.some((job) => job.status === "succeeded") && (
                  <form onSubmit={(event) => void materializeFeatures(event)}>
                    <label>Approved feature schema<select name="feature_schema_id" required>{featureSchemas.filter((schema) => schema.lifecycle_state === "approved").map((schema) => <option key={schema.id} value={schema.id}>{schema.name} v{schema.version}</option>)}</select></label>
                    <label>Completed ingestion job<select name="ingestion_job_id" required>{ingestionJobs.filter((job) => job.status === "succeeded").map((job) => <option key={job.id} value={job.id}>{job.source_type} · {job.id.slice(0, 8)}</option>)}</select></label>
                    <button type="submit">Materialize bounded features</button>
                  </form>
                )}
              </section>
            )}

            {can("datasets:read") && (
              <section className="panel">
                <h2>Dataset governance</h2>
                <p>Investigation metadata only. Sprint 4 has no dataset download, preview, export, or model controls.</p>
                <ul>{datasets.map((dataset) => <li key={dataset.id}>{dataset.name} · {dataset.version} · {dataset.status} · acquisition {dataset.acquisition_authorized ? "authorized" : "not authorized"}</li>)}</ul>
              </section>
            )}

            {can("alerts:read") && (
              <section className="panel">
                <h2>Deterministic alerts</h2>
                <p role="status">Live updates: {liveAlerts ? "connected" : "polling fallback"}</p>
                <ul>
                  {alerts.map((alert) => (
                    <li key={alert.id}>
                      {alert.severity} · {alert.category} · {alert.source_type} · occurrences {alert.occurrence_count}
                    </li>
                  ))}
                </ul>
              </section>
            )}

            {can("rules:read") && (
              <section className="panel">
                <h2>Detection rules</h2>
                <p>Thresholds and evidence are versioned. Rules never invoke prevention.</p>
                <ul>
                  {rules.map((rule) => (
                    <li key={rule.id}>
                      <strong>{rule.name}</strong> v{rule.version} · {rule.lifecycle_state}
                      {rule.is_active ? " · active" : ""}
                      <p>{rule.false_positive_guidance}</p>
                      {can("rules:review") && rule.lifecycle_state === "draft" && (
                        <button className="secondary" onClick={() => void reviewRule(rule)}>Approve reviewed draft</button>
                      )}
                      {can("rules:activate") && rule.lifecycle_state === "approved" && !rule.is_active && (
                        <button className="secondary" onClick={() => void activateRule(rule)}>Activate version</button>
                      )}
                      {can("rules:write") && rule.is_active && (
                        <form onSubmit={(event) => void createRuleDraft(event, rule)}>
                          <label>New threshold<input name="threshold" type="number" min="2" max="100000" required /></label>
                          <button type="submit">Create draft version</button>
                        </form>
                      )}
                    </li>
                  ))}
                </ul>
              </section>
            )}

            {can("telemetry:read") && (
              <section className="panel">
                <h2>Telemetry ingestion</h2>
                <p>Only controlled metadata files are accepted. Uploaded content is treated as hostile.</p>
                <ul>
                  {ingestionJobs.map((job) => (
                    <li key={job.id}>
                      {job.source_type} · {job.status} · accepted {job.accepted_records} · rejected {job.rejected_records} · duplicate {job.duplicate_records}
                      {job.error_code ? ` · ${job.error_code}` : ""}
                    </li>
                  ))}
                </ul>
                {can("ingestion:submit") && (
                  <form encType="multipart/form-data" onSubmit={(event) => void submitTelemetry(event)}>
                    <label>Source type<select name="source_type" defaultValue="normalized"><option value="normalized">Canonical flow JSONL</option><option value="zeek">Zeek conn.log</option><option value="suricata">Suricata EVE JSON</option><option value="pcap">Offline PCAP</option></select></label>
                    <label>Controlled telemetry file<input name="file" type="file" required /></label>
                    <button type="submit">Submit telemetry</button>
                  </form>
                )}
              </section>
            )}

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
