//! Vitrine Brocolis 🥦 messageries, en français, anglais et espagnol, écrite
//! avec [Active](https://maxlestage.github.io/Active/) :
//!
//! - côté serveur (natif) : chaque page est rendue en HTML complet (balises
//!   SEO comprises) et servie par l'application [Vitesse](https://maxlestage.github.io/Vitesse/)
//!   du serveur Brocolis (`../server-rust`), à côté de l'API ;
//! - côté navigateur (wasm32) : les îlots interactifs (démo de chiffrement,
//!   salon en direct, état du serveur) sont hydratés par Active, et les
//!   animations de la page démarrent (film de grains WebGL, pluie de chiffres,
//!   apparitions, curseur, boutons aimantés, cartes inclinées, confettis…).
//!
//! Sans WebAssembly, tout le contenu reste lisible : il est dans le HTML.

pub mod crypto;
pub mod demo;
pub mod i18n;
pub mod islands;
pub mod ratchet;
pub mod routes;
pub mod v3;

#[cfg(not(target_arch = "wasm32"))]
pub mod server;

#[cfg(target_arch = "wasm32")]
pub mod client;

/// Le dépôt du projet.
pub const REPO_URL: &str = "https://github.com/maxlestage/Messagerie-";
/// Le projet brocolis, sur lequel l'app est bâtie.
pub const BROCOLIS_URL: &str = "https://brocolis-dafbe9beac75.herokuapp.com/";
/// Le texte complet de la licence.
pub const LICENSE_FILE: &str = "https://github.com/maxlestage/Messagerie-/blob/master/LICENSE";
/// Les fichiers bruts du dépôt (images du README).
pub const RAW_URL: &str = "https://raw.githubusercontent.com/maxlestage/Messagerie-/master";

/// Les briques, présentées sur la page Serveur et dans le pied de page :
/// Paquets, le framework, et les quatre paquets qu'il assemble.
pub const STACK: [(&str, &str, &str, &str); 5] = [
    (
        "📦",
        "Paquets",
        "https://maxlestage.github.io/Paquets/",
        "server.stack.paquets",
    ),
    (
        "⚡",
        "Vitesse",
        "https://maxlestage.github.io/Vitesse/",
        "server.stack.vitesse",
    ),
    (
        "🛡️",
        "Securite",
        "https://maxlestage.github.io/Securite/",
        "server.stack.securite",
    ),
    (
        "💾",
        "Memoire",
        "https://maxlestage.github.io/Memoire/",
        "server.stack.memoire",
    ),
    (
        "🌿",
        "Active",
        "https://maxlestage.github.io/Active/",
        "server.stack.active",
    ),
];

/// Les thèmes : vert (défaut), clair, sombre.
pub const THEMES: [(&str, &str, &str); 3] = [
    ("green", "🥦", "theme.green"),
    ("light", "☀️", "theme.light"),
    ("dark", "🌙", "theme.dark"),
];

/// Le cookie du thème choisi (lu par le serveur : pas d'éclair de la mauvaise
/// couleur au chargement).
pub const THEME_COOKIE: &str = "brocolis-theme";
/// Le cookie de la langue choisie dans le sélecteur.
pub const LANG_COOKIE: &str = "brocolis-lang";
/// Le cookie qui ne joue le rideau d'ouverture qu'une fois par visite.
pub const INTRO_COOKIE: &str = "brocolis-intro";

/// Un thème connu, ou `None`.
pub fn theme(code: &str) -> Option<&'static str> {
    THEMES.iter().map(|(c, _, _)| *c).find(|c| *c == code)
}
