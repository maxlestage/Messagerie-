import { useT } from "../i18n/LangContext";

const LICENSE_FILE = "https://github.com/maxlestage/Messagerie-/blob/master/LICENSE";

export function LicensePage() {
  const t = useT();
  return (
    <section className="legal">
      <h1>{t("license.title")}</h1>
      <p className="legal-copyright">{t("license.copyright")}</p>
      <p>{t("license.p1")}</p>
      <p>{t("license.p2")}</p>
      <p>{t("license.p3")}</p>
      <p className="legal-warranty">{t("license.warranty")}</p>
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
