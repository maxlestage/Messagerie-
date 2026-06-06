import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export const THEMES = ["green", "light", "dark"] as const;
export type Theme = (typeof THEMES)[number];

type Ctx = {
  theme: Theme;
  setTheme: (t: Theme) => void;
};

const ThemeCtx = createContext<Ctx | null>(null);

function detectTheme(): Theme {
  try {
    const s = localStorage.getItem("messagerie.theme");
    if (s === "green" || s === "light" || s === "dark") return s;
  } catch {
    // ignore
  }
  return "green";
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() => detectTheme());

  const setTheme = (t: Theme) => {
    setThemeState(t);
    try {
      localStorage.setItem("messagerie.theme", t);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  const value = useMemo<Ctx>(() => ({ theme, setTheme }), [theme]);

  return <ThemeCtx.Provider value={value}>{children}</ThemeCtx.Provider>;
}

export function useTheme() {
  const v = useContext(ThemeCtx);
  if (!v) throw new Error("useTheme must be used within ThemeProvider");
  return v;
}
