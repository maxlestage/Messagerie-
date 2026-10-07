//! Adresses du projet.

pub const REPO_URL: &str = "https://github.com/maxlestage/Messagerie-";
pub const BROCOLIS_URL: &str = "https://maxlestage.github.io/brocolis/";
pub const LICENSE_FILE: &str = "https://github.com/maxlestage/Messagerie-/blob/master/LICENSE";

/// Adresse de production du serveur de rendez-vous — la même que celle codée
/// en dur dans l'app iOS (`BrocolisKeyStore.serverURL`). À changer ICI si le
/// serveur déménage.
pub const SERVER_URL: &str = "https://brocolis-serveur-839b43057467.herokuapp.com";

/// Quand la vitrine est servie PAR le serveur lui-même (sur /site/), on
/// interroge la même origine : la page Serveur montre alors toujours l'état du
/// serveur qui héberge la page. Sinon (GitHub Pages, dev local), on retombe
/// sur l'adresse de production.
pub fn server_base() -> String {
    let location = gloo::utils::window().location();
    match (location.pathname(), location.origin()) {
        (Ok(path), Ok(origin)) if path.starts_with("/site") => origin,
        _ => SERVER_URL.to_string(),
    }
}
