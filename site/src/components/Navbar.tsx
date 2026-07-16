import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useT } from "../i18n/LangContext";
import type { I18nKey } from "../i18n/dict";
import { Switchers } from "./Switchers";

const REPO_URL = "https://github.com/maxlestage/Messagerie-";
const BROCOLIS_URL = "https://maxlestage.github.io/brocolis/";

// Trois sortes d'entrées : ancres de l'accueil, routes du site, liens externes.
type NavItem =
  | { kind: "section"; id: string; key: I18nKey }
  | { kind: "route"; to: string; key: I18nKey }
  | { kind: "external"; href: string; key: I18nKey };

const NAV_ITEMS: ReadonlyArray<NavItem> = [
  { kind: "section", id: "features", key: "nav.features" },
  { kind: "section", id: "doc", key: "nav.doc" },
  { kind: "route", to: "/salon", key: "nav.salon" },
  { kind: "route", to: "/serveur", key: "nav.server" },
  { kind: "route", to: "/license", key: "nav.license" },
  { kind: "external", href: BROCOLIS_URL, key: "nav.brocolis" },
  { kind: "external", href: REPO_URL, key: "nav.github" },
];

export function Navbar() {
  const t = useT();
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  const close = () => setOpen(false);

  // Ancre d'une section de l'accueil : si on est ailleurs, on revient d'abord
  // sur l'accueil, puis on défile jusqu'à la section.
  const goSection = (id: string) => (e: React.MouseEvent) => {
    e.preventDefault();
    close();
    if (location.pathname !== "/") navigate("/");
    requestAnimationFrame(() =>
      requestAnimationFrame(() =>
        document.getElementById(id)?.scrollIntoView({ behavior: "smooth" })
      )
    );
  };

  return (
    <nav className="navbar">
      <div className="nav-inner">
        <Link className="nav-brand" to="/" onClick={close}>
          <span className="nav-leaf" aria-hidden="true">🥦</span>
          <span>Brocolis messageries</span>
        </Link>

        <button
          type="button"
          className={`nav-toggle ${open ? "open" : ""}`}
          aria-label={t("nav.menu")}
          aria-expanded={open}
          onClick={() => setOpen((v) => !v)}
        >
          <span />
          <span />
          <span />
        </button>

        <div className={`nav-drawer ${open ? "open" : ""}`}>
          <ul className="nav-links">
            {NAV_ITEMS.map((item) => (
              <li key={item.key}>
                {item.kind === "section" ? (
                  <a href={`#/${item.id}`} onClick={goSection(item.id)}>
                    {t(item.key)}
                  </a>
                ) : item.kind === "route" ? (
                  <Link to={item.to} onClick={close}>
                    {t(item.key)}
                  </Link>
                ) : (
                  <a href={item.href} onClick={close} target="_blank" rel="noopener noreferrer">
                    {t(item.key)}
                  </a>
                )}
              </li>
            ))}
          </ul>
          <div className="nav-switchers">
            <Switchers />
          </div>
        </div>
      </div>
    </nav>
  );
}
