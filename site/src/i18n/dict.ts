export const LANGS = ["fr", "en", "es"] as const;
export type Lang = (typeof LANGS)[number];

const BROCOLIS = "https://maxlestage.github.io/brocolis/";

export const DICT = {
  fr: {
    "meta.title": "Brocolis 🥦 messageries — chiffrement sélectif",
    "meta.desc":
      "Brocolis messageries : ajoute le chiffrement sélectif de brocolis à tes apps de messagerie iOS via une extension de partage. Appairage X25519, clé de groupe, expiration.",
    "meta.ogTitle": "Brocolis 🥦 messageries",
    "meta.ogDesc": "Chiffrement sélectif pour tes messageries, bâti sur brocolis.",
    "hero.alt": "Brocolis messageries",
    "hero.tagline": `Chiffrement sélectif pour tes messageries — bâti sur <a href="${BROCOLIS}">brocolis</a>.`,
    "cta.repo": "Voir le dépôt",
    "cta.brocolis": "Projet brocolis",
    "nav.features": "Fonctionnalités",
    "nav.doc": "Documentation",
    "nav.github": "GitHub",
    "nav.brocolis": "brocolis",
    "nav.menu": "Menu",
    "switch.lang": "Langue",
    "switch.theme": "Thème",
    "theme.green": "Vert",
    "theme.light": "Clair",
    "theme.dark": "Sombre",
    "feat.graft.t": "Se greffe sur tes apps",
    "feat.graft.d":
      "Extension de partage iOS : sélectionne du texte dans WhatsApp, iMessage, Notes… → Partager → Brocolis 🥦.",
    "feat.crypto.t": "Chiffrement sélectif",
    "feat.crypto.d":
      "Seuls les ((secrets)) deviennent des jetons [[BROCOLIS:v1:…]] (AES-256-GCM). Le service distant ne voit que du chiffré.",
    "feat.pair.t": "Appairage automatique",
    "feat.pair.d":
      "Échange de clés X25519 via un code court : chaque appareil obtient la clé de l’autre, sans copier-coller.",
    "feat.group.t": "Clé de groupe",
    "feat.group.d":
      "Un fondateur génère une clé de groupe et la distribue chiffrée à chaque membre (key-wrapping X25519).",
    "feat.rotate.t": "Rotation & expiration",
    "feat.rotate.d":
      "Validité configurable, purge automatique à l’ouverture, préavis par notification et action « Prolonger ».",
    "feat.interop.t": "Compatible brocolis",
    "feat.interop.d":
      "Même format de jeton que le proxy Rust brocolis : interopérable des deux côtés.",
    "doc.title": "Documentation",
    "doc.note": "Le README du dépôt (en français).",
    "doc.loading": "Chargement du README…",
    "doc.unavailable": "README indisponible — voir le dépôt.",
    "nav.license": "Licence",
    "nav.server": "Serveur",
    "nav.salon": "Salon",
    "cta.server": "Serveur 🛰️",
    "cta.salon": "Salon des rendez-vous 🤝",
    "server.title": "Serveur de rendez-vous",
    "server.note": "L'espace dédié qui héberge l'API d'appairage… et cette vitrine.",
    "server.status": "État",
    "server.checking": "Vérification…",
    "server.online": "En ligne",
    "server.offline": "Hors ligne",
    "server.latency": "réponse en",
    "server.address": "Adresse",
    "server.open": "Ouvrir le serveur",
    "server.recheck": "Re-vérifier",
    "server.api": "Points d'accès",
    "server.api.pair": "échange des clés publiques (appairage)",
    "server.api.wrap": "distribution de la clé de groupe (chiffrée)",
    "server.api.health": "état du service",
    "server.privacy":
      "Le serveur ne voit que des clés publiques et des blobs chiffrés, jamais la clé secrète ni les messages.",
    "server.back": "← Retour à l'accueil",
    "license.title": "Licence",
    "license.copyright": "© 2026 LESTAGE Maxime Nathan — Tous droits réservés.",
    "license.p1": "Logiciel propriétaire. Cette application (app iOS, extension de partage, serveur de rendez-vous et site) ainsi que son code source sont la propriété exclusive de LESTAGE Maxime Nathan.",
    "license.p2": "Aucun droit n'est concédé sur le code source : la copie, la modification, la distribution ou l'utilisation sont interdites sans autorisation écrite préalable de l'auteur.",
    "license.p3": "Ce projet accompagne brocolis, également propriétaire ; ses termes de licence s'appliquent.",
    "license.warranty": "Le logiciel est fourni « TEL QUEL », sans aucune garantie, explicite ou implicite. En aucun cas l'auteur ne pourra être tenu responsable d'un quelconque dommage. Utilisation à vos propres risques.",
    "license.viewFile": "Voir le fichier LICENSE complet →",
    "license.back": "← Retour à l'accueil",
    "license.note": "Texte de la licence :",
    "license.unavailable": "Licence indisponible — voir le fichier sur GitHub :",
    "license.full": `Copyright © 2026 LESTAGE Maxime Nathan. Tous droits réservés.

Licence propriétaire — All rights reserved.

Ce logiciel (« Brocolis 🥦 », l'application iOS, son extension, le serveur de
rendez-vous et le site) ainsi que son code source sont la propriété exclusive de
LESTAGE Maxime Nathan. Ils ne peuvent être copiés, modifiés, distribués, publiés
ni utilisés, en tout ou partie, sans autorisation écrite préalable de l'auteur.

Aucun droit, licence ou titre n'est concédé sur le code source. Toute copie,
modification, distribution ou utilisation en violation de la présente licence
est strictement interdite et passible de poursuites.

Ce logiciel accompagne le projet brocolis
(https://github.com/maxlestage/brocolis), également propriété exclusive de
LESTAGE Maxime Nathan ; ses termes de licence propriétaire s'appliquent
également.

LE LOGICIEL EST FOURNI « TEL QUEL », SANS AUCUNE GARANTIE, EXPLICITE OU
IMPLICITE, Y COMPRIS, SANS S'Y LIMITER, LES GARANTIES IMPLICITES DE QUALITÉ
MARCHANDE ET D'ADÉQUATION À UN USAGE PARTICULIER. EN AUCUN CAS L'AUTEUR NE
POURRA ÊTRE TENU RESPONSABLE D'UN QUELCONQUE DOMMAGE, DIRECT OU INDIRECT,
DÉCOULANT DE L'UTILISATION OU DE L'IMPOSSIBILITÉ D'UTILISER CE LOGICIEL.
UTILISATION À VOS PROPRES RISQUES.`,
    "footer.tagline": "Brocolis messageries 🥦 — chiffrement sélectif pour tes messageries. Le contenu de cette page reflète le README du dépôt.",
  },
  en: {
    "meta.title": "Brocolis 🥦 messaging — selective encryption",
    "meta.desc":
      "Brocolis messaging: adds brocolis selective encryption to your iOS messaging apps via a share extension. X25519 pairing, group key, expiry.",
    "meta.ogTitle": "Brocolis 🥦 messaging",
    "meta.ogDesc": "Selective encryption for your messaging apps, built on brocolis.",
    "hero.alt": "Brocolis messaging",
    "hero.tagline": `Selective encryption for your messaging apps — built on <a href="${BROCOLIS}">brocolis</a>.`,
    "cta.repo": "View the repo",
    "cta.brocolis": "brocolis project",
    "nav.features": "Features",
    "nav.doc": "Documentation",
    "nav.github": "GitHub",
    "nav.brocolis": "brocolis",
    "nav.menu": "Menu",
    "switch.lang": "Language",
    "switch.theme": "Theme",
    "theme.green": "Green",
    "theme.light": "Light",
    "theme.dark": "Dark",
    "feat.graft.t": "Hooks into your apps",
    "feat.graft.d":
      "iOS share extension: select text in WhatsApp, iMessage, Notes… → Share → Brocolis 🥦.",
    "feat.crypto.t": "Selective encryption",
    "feat.crypto.d":
      "Only ((secrets)) become [[BROCOLIS:v1:…]] tokens (AES-256-GCM). The remote service only ever sees ciphertext.",
    "feat.pair.t": "Automatic pairing",
    "feat.pair.d":
      "X25519 key exchange via a short code: each device gets the other's key, no copy-paste.",
    "feat.group.t": "Group key",
    "feat.group.d":
      "A founder generates a group key and distributes it encrypted to each member (X25519 key-wrapping).",
    "feat.rotate.t": "Rotation & expiry",
    "feat.rotate.d":
      "Configurable validity, auto-purge on launch, an expiry notice and a “Renew” action.",
    "feat.interop.t": "Brocolis-compatible",
    "feat.interop.d":
      "Same token format as the Rust brocolis proxy: interoperable both ways.",
    "doc.title": "Documentation",
    "doc.note": "The repository README (in French).",
    "doc.loading": "Loading README…",
    "doc.unavailable": "README unavailable — see the repository.",
    "nav.license": "License",
    "nav.server": "Server",
    "nav.salon": "Room",
    "cta.server": "Server 🛰️",
    "cta.salon": "Pairing room 🤝",
    "server.title": "Rendezvous server",
    "server.note": "The dedicated space hosting the pairing API… and this very site.",
    "server.status": "Status",
    "server.checking": "Checking…",
    "server.online": "Online",
    "server.offline": "Offline",
    "server.latency": "answered in",
    "server.address": "Address",
    "server.open": "Open the server",
    "server.recheck": "Check again",
    "server.api": "Endpoints",
    "server.api.pair": "public-key exchange (pairing)",
    "server.api.wrap": "group-key distribution (encrypted)",
    "server.api.health": "service health",
    "server.privacy":
      "The server only ever sees public keys and encrypted blobs — never the secret key or your messages.",
    "server.back": "← Back to home",
    "license.title": "License",
    "license.copyright": "© 2026 LESTAGE Maxime Nathan — All rights reserved.",
    "license.p1": "Proprietary software. This application (iOS app, share extension, rendezvous server and website) and its source code are the exclusive property of LESTAGE Maxime Nathan.",
    "license.p2": "No rights are granted over the source code: copying, modifying, distributing or using it is forbidden without the author's prior written permission.",
    "license.p3": "This project accompanies brocolis, also proprietary; its license terms apply.",
    "license.warranty": "The software is provided “AS IS”, without warranty of any kind, express or implied. In no event shall the author be liable for any damages. Use at your own risk.",
    "license.viewFile": "View the full LICENSE file →",
    "license.back": "← Back to home",
    "license.note": "License text:",
    "license.unavailable": "License unavailable — see the file on GitHub:",
    "license.full": `Copyright © 2026 LESTAGE Maxime Nathan. All rights reserved.

Proprietary license — All rights reserved.

This software (“Brocolis 🥦”, the iOS app, its extension, the rendezvous server
and the website) and its source code are the exclusive property of LESTAGE
Maxime Nathan. They may not be copied, modified, distributed, published or used,
in whole or in part, without the author's prior written permission.

No right, license or title is granted over the source code. Any copy,
modification, distribution or use in violation of this license is strictly
prohibited and liable to prosecution.

This software accompanies the brocolis project
(https://github.com/maxlestage/brocolis), also the exclusive property of LESTAGE
Maxime Nathan; its proprietary license terms apply as well.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY DAMAGE, DIRECT OR INDIRECT, ARISING FROM THE USE OF OR INABILITY TO USE THIS
SOFTWARE. USE AT YOUR OWN RISK.`,
    "footer.tagline": "Brocolis messaging 🥦 — selective encryption for your messaging apps. This page mirrors the repository README.",
  },
  es: {
    "meta.title": "Brocolis 🥦 mensajería — cifrado selectivo",
    "meta.desc":
      "Brocolis mensajería: añade el cifrado selectivo de brocolis a tus apps de mensajería iOS mediante una extensión de compartir. Emparejamiento X25519, clave de grupo, caducidad.",
    "meta.ogTitle": "Brocolis 🥦 mensajería",
    "meta.ogDesc": "Cifrado selectivo para tus mensajerías, basado en brocolis.",
    "hero.alt": "Brocolis mensajería",
    "hero.tagline": `Cifrado selectivo para tus mensajerías — basado en <a href="${BROCOLIS}">brocolis</a>.`,
    "cta.repo": "Ver el repositorio",
    "cta.brocolis": "Proyecto brocolis",
    "nav.features": "Funciones",
    "nav.doc": "Documentación",
    "nav.github": "GitHub",
    "nav.brocolis": "brocolis",
    "nav.menu": "Menú",
    "switch.lang": "Idioma",
    "switch.theme": "Tema",
    "theme.green": "Verde",
    "theme.light": "Claro",
    "theme.dark": "Oscuro",
    "feat.graft.t": "Se integra en tus apps",
    "feat.graft.d":
      "Extensión de compartir iOS: selecciona texto en WhatsApp, iMessage, Notas… → Compartir → Brocolis 🥦.",
    "feat.crypto.t": "Cifrado selectivo",
    "feat.crypto.d":
      "Solo los ((secretos)) se vuelven tokens [[BROCOLIS:v1:…]] (AES-256-GCM). El servicio remoto solo ve cifrado.",
    "feat.pair.t": "Emparejamiento automático",
    "feat.pair.d":
      "Intercambio de claves X25519 con un código corto: cada dispositivo obtiene la clave del otro, sin copiar y pegar.",
    "feat.group.t": "Clave de grupo",
    "feat.group.d":
      "Un fundador genera una clave de grupo y la distribuye cifrada a cada miembro (key-wrapping X25519).",
    "feat.rotate.t": "Rotación y caducidad",
    "feat.rotate.d":
      "Validez configurable, purga automática al abrir, aviso por notificación y acción «Renovar».",
    "feat.interop.t": "Compatible con brocolis",
    "feat.interop.d":
      "Mismo formato de token que el proxy Rust brocolis: interoperable en ambos sentidos.",
    "doc.title": "Documentación",
    "doc.note": "El README del repositorio (en francés).",
    "doc.loading": "Cargando README…",
    "doc.unavailable": "README no disponible — consulta el repositorio.",
    "nav.license": "Licencia",
    "nav.server": "Servidor",
    "nav.salon": "Sala",
    "cta.server": "Servidor 🛰️",
    "cta.salon": "Sala de emparejamiento 🤝",
    "server.title": "Servidor de encuentro",
    "server.note": "El espacio dedicado que aloja la API de emparejamiento… y este sitio.",
    "server.status": "Estado",
    "server.checking": "Comprobando…",
    "server.online": "En línea",
    "server.offline": "Fuera de línea",
    "server.latency": "respondió en",
    "server.address": "Dirección",
    "server.open": "Abrir el servidor",
    "server.recheck": "Volver a comprobar",
    "server.api": "Puntos de acceso",
    "server.api.pair": "intercambio de claves públicas (emparejamiento)",
    "server.api.wrap": "distribución de la clave de grupo (cifrada)",
    "server.api.health": "estado del servicio",
    "server.privacy":
      "El servidor solo ve claves públicas y blobs cifrados — nunca la clave secreta ni tus mensajes.",
    "server.back": "← Volver al inicio",
    "license.title": "Licencia",
    "license.copyright": "© 2026 LESTAGE Maxime Nathan — Todos los derechos reservados.",
    "license.p1": "Software propietario. Esta aplicación (app iOS, extensión de compartir, servidor de encuentro y sitio web) y su código fuente son propiedad exclusiva de LESTAGE Maxime Nathan.",
    "license.p2": "No se concede ningún derecho sobre el código fuente: copiar, modificar, distribuir o usarlo está prohibido sin autorización escrita previa del autor.",
    "license.p3": "Este proyecto acompaña a brocolis, también propietario; se aplican sus términos de licencia.",
    "license.warranty": "El software se proporciona «TAL CUAL», sin garantía de ningún tipo, expresa o implícita. En ningún caso el autor será responsable de daño alguno. Úsalo bajo tu propia responsabilidad.",
    "license.viewFile": "Ver el archivo LICENSE completo →",
    "license.back": "← Volver al inicio",
    "license.note": "Texto de la licencia:",
    "license.unavailable": "Licencia no disponible — consulta el archivo en GitHub:",
    "license.full": `Copyright © 2026 LESTAGE Maxime Nathan. Todos los derechos reservados.

Licencia propietaria — All rights reserved.

Este software («Brocolis 🥦», la aplicación iOS, su extensión, el servidor de
encuentro y el sitio web) y su código fuente son propiedad exclusiva de LESTAGE
Maxime Nathan. No pueden ser copiados, modificados, distribuidos, publicados ni
utilizados, en todo o en parte, sin autorización escrita previa del autor.

No se concede ningún derecho, licencia ni título sobre el código fuente.
Cualquier copia, modificación, distribución o uso que infrinja esta licencia
está estrictamente prohibido y es objeto de acciones legales.

Este software acompaña al proyecto brocolis
(https://github.com/maxlestage/brocolis), también propiedad exclusiva de LESTAGE
Maxime Nathan; se aplican igualmente sus términos de licencia propietaria.

EL SOFTWARE SE PROPORCIONA «TAL CUAL», SIN GARANTÍA DE NINGÚN TIPO, EXPRESA O
IMPLÍCITA, INCLUIDAS, ENTRE OTRAS, LAS GARANTÍAS IMPLÍCITAS DE COMERCIABILIDAD Y
ADECUACIÓN A UN FIN DETERMINADO. EN NINGÚN CASO EL AUTOR SERÁ RESPONSABLE DE
NINGÚN DAÑO, DIRECTO O INDIRECTO, DERIVADO DEL USO O LA IMPOSIBILIDAD DE USAR
ESTE SOFTWARE. ÚSALO BAJO TU PROPIA RESPONSABILIDAD.`,
    "footer.tagline": "Brocolis mensajería 🥦 — cifrado selectivo para tus mensajerías. Esta página refleja el README del repositorio.",
  },
} as const;

export type I18nKey = keyof (typeof DICT)["fr"];
