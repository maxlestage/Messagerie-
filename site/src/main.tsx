import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";
import "highlight.js/styles/github-dark.css";
import { ThemeProvider } from "./theme/ThemeContext";
import { LangProvider } from "./i18n/LangContext";

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider>
      <LangProvider>
        <App />
      </LangProvider>
    </ThemeProvider>
  </React.StrictMode>,
);
