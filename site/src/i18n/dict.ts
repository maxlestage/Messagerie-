export const LANGS = ["fr", "en", "es"] as const;
export type Lang = (typeof LANGS)[number];

const BROCOLIS = "https://maxlestage.github.io/brocolis/";

export const DICT = {
  fr: {
    "meta.title": "Brocolis messageries — chiffrement sélectif",
    "meta.desc":
      "Brocolis messageries : ajoute le chiffrement sélectif de brocolis à tes apps de messagerie iOS via une extension de partage. Appairage X25519, clé de groupe, expiration.",
    "meta.ogTitle": "Brocolis messageries 🥦",
    "meta.ogDesc": "Chiffrement sélectif pour tes messageries, bâti sur brocolis.",
    "hero.alt": "Brocolis messageries",
    "hero.tagline": `Chiffrement sélectif pour tes messageries — bâti sur <a href="${BROCOLIS}">brocolis</a>.`,
    "cta.repo": "Voir le dépôt",
    "cta.brocolis": "Projet brocolis",
    "nav.features": "Fonctionnalités",
    "nav.doc": "Documentation",
    "nav.github": "GitHub",
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
    "footer.html": `Brocolis messageries 🥦 — chiffrement sélectif pour tes messageries, bâti sur <a href="${BROCOLIS}">brocolis</a>. Le contenu de cette page reflète le README du dépôt.`,
  },
  en: {
    "meta.title": "Brocolis messaging — selective encryption",
    "meta.desc":
      "Brocolis messaging: adds brocolis selective encryption to your iOS messaging apps via a share extension. X25519 pairing, group key, expiry.",
    "meta.ogTitle": "Brocolis messaging 🥦",
    "meta.ogDesc": "Selective encryption for your messaging apps, built on brocolis.",
    "hero.alt": "Brocolis messaging",
    "hero.tagline": `Selective encryption for your messaging apps — built on <a href="${BROCOLIS}">brocolis</a>.`,
    "cta.repo": "View the repo",
    "cta.brocolis": "brocolis project",
    "nav.features": "Features",
    "nav.doc": "Documentation",
    "nav.github": "GitHub",
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
    "footer.html": `Brocolis messaging 🥦 — selective encryption for your messaging apps, built on <a href="${BROCOLIS}">brocolis</a>. This page mirrors the repository README.`,
  },
  es: {
    "meta.title": "Brocolis mensajería — cifrado selectivo",
    "meta.desc":
      "Brocolis mensajería: añade el cifrado selectivo de brocolis a tus apps de mensajería iOS mediante una extensión de compartir. Emparejamiento X25519, clave de grupo, caducidad.",
    "meta.ogTitle": "Brocolis mensajería 🥦",
    "meta.ogDesc": "Cifrado selectivo para tus mensajerías, basado en brocolis.",
    "hero.alt": "Brocolis mensajería",
    "hero.tagline": `Cifrado selectivo para tus mensajerías — basado en <a href="${BROCOLIS}">brocolis</a>.`,
    "cta.repo": "Ver el repositorio",
    "cta.brocolis": "Proyecto brocolis",
    "nav.features": "Funciones",
    "nav.doc": "Documentación",
    "nav.github": "GitHub",
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
    "footer.html": `Brocolis mensajería 🥦 — cifrado selectivo para tus mensajerías, basado en <a href="${BROCOLIS}">brocolis</a>. Esta página refleja el README del repositorio.`,
  },
} as const;

export type I18nKey = keyof (typeof DICT)["fr"];
