import React from "react";
import { createRoot } from "react-dom/client";
import { HashRouter } from "react-router-dom";
import App from "./App";
import "./styles.css";
import "highlight.js/styles/github-dark.css";
import { ThemeProvider } from "./theme/ThemeContext";
import { LangProvider } from "./i18n/LangContext";

// HashRouter : le site est servi statiquement (sur /site/ du serveur de
// rendez-vous), sans réécriture côté serveur — le hash évite tout 404 au
// rechargement, et les anciens liens #/license restent valides.
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider>
      <LangProvider>
        <HashRouter>
          <App />
        </HashRouter>
      </LangProvider>
    </ThemeProvider>
  </React.StrictMode>,
);
