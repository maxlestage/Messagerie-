// Copie le README du dépôt dans public/ pour que le site reste aligné dessus.
import { copyFileSync, mkdirSync } from 'node:fs';

mkdirSync('public', { recursive: true });
copyFileSync('../README.md', 'public/README.md');
console.log('README.md copié dans site/public/');
