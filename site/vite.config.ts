import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// `base: './'` rend les chemins relatifs : le site marche aussi bien à la racine
// qu'en sous-chemin (GitHub Pages de projet, ex. /Messagerie-/).
export default defineConfig({
  base: './',
  plugins: [react()],
});
