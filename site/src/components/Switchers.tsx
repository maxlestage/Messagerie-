import { useLang, useT } from "../i18n/LangContext";
import { LANGS } from "../i18n/dict";
import { THEMES, useTheme, type Theme } from "../theme/ThemeContext";

const THEME_ICON: Record<Theme, string> = {
  green: "🥦",
  light: "☀",
  dark: "🌙",
};

const THEME_LABEL_KEY = {
  green: "theme.green",
  light: "theme.light",
  dark: "theme.dark",
} as const;

export function Switchers() {
  const t = useT();
  const { lang, setLang } = useLang();
  const { theme, setTheme } = useTheme();

  return (
    <div className="switchers">
      <div className="switcher" role="group" aria-label={t("switch.lang")}>
        {LANGS.map((l) => (
          <button
            key={l}
            type="button"
            className={`pill ${lang === l ? "active" : ""}`}
            aria-pressed={lang === l}
            onClick={() => setLang(l)}
          >
            {l.toUpperCase()}
          </button>
        ))}
      </div>
      <div className="switcher" role="group" aria-label={t("switch.theme")}>
        {THEMES.map((th) => (
          <button
            key={th}
            type="button"
            className={`pill ${theme === th ? "active" : ""}`}
            aria-pressed={theme === th}
            title={t(THEME_LABEL_KEY[th])}
            onClick={() => setTheme(th)}
          >
            {THEME_ICON[th]}
          </button>
        ))}
      </div>
    </div>
  );
}
