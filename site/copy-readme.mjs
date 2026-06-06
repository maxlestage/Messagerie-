// Copie le README et la LICENSE du dépôt dans public/ pour que le site reste
// aligné dessus (rendus tels quels).
import { copyFileSync, mkdirSync } from "node:fs";

mkdirSync("public", { recursive: true });
copyFileSync("../README.md", "public/README.md");
copyFileSync("../LICENSE", "public/LICENSE.txt");
console.log("README.md et LICENSE copiés dans site/public/");
