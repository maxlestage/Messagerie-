import { useEffect, useState } from "react";
import Markdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeHighlight from "rehype-highlight";
import { useT } from "./i18n/LangContext";
import type { I18nKey } from "./i18n/dict";
import { Navbar } from "./components/Navbar";
import { LicensePage } from "./components/LicensePage";

type Route = "home" | "license";
function getRoute(): Route {
  return window.location.hash.startsWith("#/license") ? "license" : "home";
}

const REPO_URL = "https://github.com/maxlestage/Messagerie-";
const BROCOLIS_URL = "https://maxlestage.github.io/brocolis/";

// Les liens relatifs du README (LICENSE, site/, server/…) doivent pointer vers
// le dépôt GitHub, pas vers le site. On garde tels quels les liens absolus/ancres.
function resolveHref(href?: string): string {
  if (!href) return "#";
  if (/^(https?:|mailto:|#)/i.test(href)) return href;
  const clean = href.replace(/^\.?\//, "");
  const kind = href.endsWith("/") ? "tree" : "blob";
  return `${REPO_URL}/${kind}/master/${clean}`;
}

const mdComponents: Components = {
  a({ href, children }) {
    const url = resolveHref(href);
    const external = /^https?:/i.test(url);
    return external ? (
      <a href={url} target="_blank" rel="noopener noreferrer">
        {children}
      </a>
    ) : (
      <a href={url}>{children}</a>
    );
  },
};

const FEATURES: { icon: string; title: I18nKey; text: I18nKey }[] = [
  { icon: "🧩", title: "feat.graft.t", text: "feat.graft.d" },
  { icon: "🔒", title: "feat.crypto.t", text: "feat.crypto.d" },
  { icon: "🤝", title: "feat.pair.t", text: "feat.pair.d" },
  { icon: "👥", title: "feat.group.t", text: "feat.group.d" },
  { icon: "⏳", title: "feat.rotate.t", text: "feat.rotate.d" },
  { icon: "🥦", title: "feat.interop.t", text: "feat.interop.d" },
];

export default function App() {
  const t = useT();
  const [readme, setReadme] = useState<string | null>(null);
  const [route, setRoute] = useState<Route>(getRoute());

  useEffect(() => {
    const onHash = () => setRoute(getRoute());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // Au changement de page, remonte en haut (licence) ou rejoint l'ancre (accueil).
  useEffect(() => {
    if (route === "license") {
      window.scrollTo(0, 0);
      return;
    }
    const h = window.location.hash;
    if (h.length > 1 && !h.startsWith("#/")) {
      document.getElementById(h.slice(1))?.scrollIntoView();
    }
  }, [route]);

  useEffect(() => {
    fetch("README.md")
      .then((r) => (r.ok ? r.text() : Promise.reject(r.status)))
      .then(setReadme)
      .catch(() => setReadme(""));
  }, []);

  return (
    <>
      <Navbar />
      <div className="page">
        {route === "license" ? (
          <LicensePage />
        ) : (
          <>
        <header className="hero" id="top">
          <div className="hero-inner">
          <img
            className="logo-img"
            src={`${import.meta.env.BASE_URL}photo.png`}
            alt={t("hero.alt")}
            width={180}
            height={180}
          />
          <h1>Brocolis messageries</h1>
          <p className="tagline" dangerouslySetInnerHTML={{ __html: t("hero.tagline") }} />
          <div className="cta">
            <a className="btn primary" href={REPO_URL}>{t("cta.repo")}</a>
            <a className="btn" href={BROCOLIS_URL}>{t("cta.brocolis")}</a>
          </div>
        </div>
      </header>

      <section className="features" id="features">
        {FEATURES.map((f) => (
          <article className="card" key={f.title}>
            <div className="card-icon">{f.icon}</div>
            <h3>{t(f.title)}</h3>
            <p>{t(f.text)}</p>
          </article>
        ))}
      </section>

      <main className="readme" id="doc">
        <h2 className="readme-title">{t("doc.title")}</h2>
        <p className="readme-note">{t("doc.note")}</p>
        {readme === null ? (
          <p className="loading">{t("doc.loading")}</p>
        ) : readme === "" ? (
          <p className="loading">
            {t("doc.unavailable")} <a href={REPO_URL}>GitHub</a>
          </p>
        ) : (
          <article className="markdown">
            <Markdown
              remarkPlugins={[remarkGfm]}
              rehypePlugins={[rehypeHighlight]}
              components={mdComponents}
            >
              {readme}
            </Markdown>
          </article>
        )}
      </main>
          </>
        )}

      <footer className="footer">
        <p dangerouslySetInnerHTML={{ __html: t("footer.html") }} />
      </footer>
      </div>
    </>
  );
}
