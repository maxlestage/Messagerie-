import { useT } from "../i18n/LangContext";

const LICENSE_FILE = "https://github.com/maxlestage/Messagerie-/blob/master/LICENSE";

export function LicensePage() {
  const t = useT();
  return (
    <section className="legal">
      <h1>{t("license.title")}</h1>
      <p className="legal-note">{t("license.note")}</p>
      <pre className="license-text">{t("license.full")}</pre>
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
