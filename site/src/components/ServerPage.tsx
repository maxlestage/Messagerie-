import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useT } from "../i18n/LangContext";
import { serverBase } from "../config";

type Status = "checking" | "online" | "offline";

const ENDPOINTS = [
  { method: "POST / GET", path: "/pair", key: "server.api.pair" as const },
  { method: "POST / GET", path: "/wrap", key: "server.api.wrap" as const },
  { method: "GET", path: "/health", key: "server.api.health" as const },
];

export function ServerPage() {
  const t = useT();
  const base = serverBase();
  const [status, setStatus] = useState<Status>("checking");
  const [latency, setLatency] = useState<number | null>(null);

  const check = useCallback(async () => {
    setStatus("checking");
    setLatency(null);
    const started = performance.now();
    try {
      const res = await fetch(`${base}/health`, { signal: AbortSignal.timeout(8000) });
      setLatency(Math.round(performance.now() - started));
      setStatus(res.ok ? "online" : "offline");
    } catch {
      // Hors de /site/ (dev local), le serveur ne renvoie pas d'en-têtes CORS :
      // on retombe sur une requête opaque — si elle aboutit, il est joignable.
      try {
        await fetch(`${base}/health`, { mode: "no-cors", signal: AbortSignal.timeout(8000) });
        setLatency(Math.round(performance.now() - started));
        setStatus("online");
      } catch {
        setStatus("offline");
      }
    }
  }, [base]);

  useEffect(() => {
    check();
  }, [check]);

  return (
    <section className="legal server-page">
      <h1>{t("server.title")} 🛰️</h1>
      <p className="legal-note">{t("server.note")}</p>

      <div className="server-card">
        <p className="server-row">
          <strong>{t("server.status")}</strong>
          <span className={`server-status ${status}`}>
            <span className="server-dot" aria-hidden="true" />
            {status === "checking" && t("server.checking")}
            {status === "online" && t("server.online")}
            {status === "offline" && t("server.offline")}
            {status === "online" && latency !== null && (
              <em>
                {" "}
                — {t("server.latency")} {latency} ms
              </em>
            )}
          </span>
        </p>
        <p className="server-row">
          <strong>{t("server.address")}</strong>
          <code className="server-url">{base}</code>
        </p>
        <div className="cta">
          <a className="btn primary" href={base} target="_blank" rel="noopener noreferrer">
            {t("server.open")}
          </a>
          <button type="button" className="btn" onClick={check}>
            {t("server.recheck")}
          </button>
        </div>
      </div>

      <h2>{t("server.api")}</h2>
      <ul className="server-endpoints">
        {ENDPOINTS.map((e) => (
          <li key={e.path}>
            <code>
              {e.method} {e.path}
            </code>{" "}
            — {t(e.key)}
          </li>
        ))}
      </ul>
      <p className="legal-note">{t("server.privacy")}</p>

      <p>
        <Link to="/">{t("server.back")}</Link>
      </p>
    </section>
  );
}
