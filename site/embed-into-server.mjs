// Recopie la vitrine pré-construite (dist/) dans server/public/, d'où le serveur
// de rendez-vous la sert sur /site/. À lancer après `npm run build`.
import { cpSync, rmSync } from "node:fs";

rmSync("../server/public", { recursive: true, force: true });
cpSync("dist", "../server/public", { recursive: true });
console.log("Vitrine copiée dans server/public/ (servie sur /site/).");
