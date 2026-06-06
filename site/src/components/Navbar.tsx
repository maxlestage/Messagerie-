import { useEffect, useState } from "react";
import { useT } from "../i18n/LangContext";
import type { I18nKey } from "../i18n/dict";
import { Switchers } from "./Switchers";

const REPO_URL = "https://github.com/maxlestage/Messagerie-";
const BROCOLIS_URL = "https://maxlestage.github.io/brocolis/";

const NAV_ITEMS: ReadonlyArray<{ href: string; key: I18nKey; external?: boolean }> = [
  { href: "#features", key: "nav.features" },
  { href: "#doc", key: "nav.doc" },
  { href: "#/license", key: "nav.license" },
  { href: BROCOLIS_URL, key: "nav.brocolis", external: true },
  { href: REPO_URL, key: "nav.github", external: true },
];

export function Navbar() {
  const t = useT();
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  const close = () => setOpen(false);

  return (
    <nav className="navbar">
      <div className="nav-inner">
        <a className="nav-brand" href="#top" onClick={close}>
          <span className="nav-leaf" aria-hidden="true">🥦</span>
          <span>Brocolis messageries</span>
        </a>

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
              <li key={item.href}>
                <a
                  href={item.href}
                  onClick={close}
                  {...(item.external ? { target: "_blank", rel: "noopener noreferrer" } : {})}
                >
                  {t(item.key)}
                </a>
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
