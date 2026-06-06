import { useEffect, useState } from "react";
import { useT } from "../i18n/LangContext";

const LICENSE_FILE = "https://github.com/maxlestage/Messagerie-/blob/master/LICENSE";

export function LicensePage() {
  const t = useT();
  const [text, setText] = useState<string | null>(null);

  useEffect(() => {
    fetch(`${import.meta.env.BASE_URL}LICENSE.txt`)
      .then((r) => (r.ok ? r.text() : Promise.reject(r.status)))
      .then(setText)
      .catch(() => setText(""));
  }, []);

  return (
    <section className="legal">
      <h1>{t("license.title")}</h1>
      <p className="legal-note">{t("license.note")}</p>

      {text === null ? (
        <p className="loading">…</p>
      ) : text === "" ? (
        <p className="loading">
          {t("license.unavailable")}{" "}
          <a href={LICENSE_FILE} target="_blank" rel="noopener noreferrer">
            LICENSE
          </a>
        </p>
      ) : (
        <pre className="license-text">{text}</pre>
      )}

      <p>
        <a href={LICENSE_FILE} target="_blank" rel="noopener noreferrer">
          {t("license.viewFile")}
        </a>
      </p>
      <p>
        <a href="#/">{t("license.back")}</a>
      </p>
    </section>
  );
}
