//! Le bouclier 🔒 : [Securite](https://maxlestage.github.io/Securite/) devant
//! chaque requête, branché par [Paquets](https://maxlestage.github.io/Paquets/).
//!
//! Dans l'ordre où passent les gardes :
//!
//! | Garde | Ce qu'il fait ici |
//! |---|---|
//! | `request_id` | un identifiant par requête (`X-Request-Id`), dans les journaux |
//! | `ban` | 20 refus (401, 403 : pare-feu, robots…) en une minute : l'adresse est bannie 15 min, puis de plus en plus longtemps. Les 429 ne comptent pas : un appareil trop bavard ne doit pas faire bannir ses voisins de box |
//! | `hygiene` | URI, en-têtes et paramètres bornés ; ni `..` ni encodage douteux |
//! | `method` | GET, HEAD, POST, PUT, PATCH, DELETE et OPTIONS seulement |
//! | `https_redirect` | HTTP → HTTPS derrière le routeur Heroku |
//! | `body_limit` | 8 Mo pour les messages (médias chiffrés), 256 Ko ailleurs |
//! | `rate_limit` | 50 req/s par adresse (rafales de 200) contre l'inondation ; les plafonds fins, par appareil et par usage, sont ceux de [`crate::limits`] |
//! | `concurrency` | 128 requêtes à la fois par adresse (flux SSE compris) |
//! | `user_agent` | les scanners connus (sqlmap, nikto, nuclei…) sont refusés |
//! | `waf` | injection SQL, XSS, RCE, Log4Shell, traversée… (sensibilité moyenne) |
//! | `csrf` | Fetch Metadata ; l'API, ouverte en CORS par choix, en est exemptée |
//! | `content_type` | les corps de l'API sont du JSON, rien d'autre |
//! | `security_headers` | CSP sur mesure, HSTS, `nosniff`, `DENY` en cadre, COOP… |
//! | `cookies` | cookies `Secure`, `HttpOnly`, `SameSite` |

use std::time::Duration;

use brocolis_site::server::Site;
use paquets::securite::prelude::*;

use crate::api::API_PREFIXES;
use crate::BODY_LIMIT;

/// Corps maximal hors envoi de messages : tous les autres corps sont de petits
/// objets JSON (clés publiques, jetons, accusés de lecture).
pub const SMALL_BODY_LIMIT: u64 = 256 * 1024;

/// Ce que peut faire une page du site, et rien de plus :
///
/// - scripts : les nôtres, le démarrage du module WebAssembly (par empreinte)
///   et la compilation WebAssembly ;
/// - styles : les nôtres, le style des îlots (par empreinte) et les attributs
///   `style` des animations (`--i`, `--d`) ;
/// - images et sons : les nôtres, et les médias déchiffrés (`data:`, `blob:`) ;
///   les images du README peuvent venir d'ailleurs en HTTPS ;
/// - réseau : le serveur lui-même (API, flux SSE) ;
/// - ni objet, ni cadre, ni formulaire vers ailleurs, ni `<base>`.
pub fn content_security_policy(site: &Site) -> ContentSecurityPolicy {
    let inline = brocolis_site::server::pages::inline_code(site);
    let mut scripts = vec!["'self'".to_owned(), "'wasm-unsafe-eval'".to_owned()];
    scripts.extend(ContentSecurityPolicy::hashes_for_inline_scripts(&inline));
    let mut styles = vec!["'self'".to_owned()];
    styles.extend(ContentSecurityPolicy::hashes_for_inline_styles(&inline));
    ContentSecurityPolicy::new()
        .default_src(["'self'"])
        .script_src(scripts)
        .style_src(styles)
        .style_src_attr(["'unsafe-inline'"])
        .img_src(["'self'", "data:", "blob:", "https:"])
        .media_src(["'self'", "data:", "blob:"])
        .font_src(["'self'", "data:"])
        .connect_src(["'self'"])
        .manifest_src(["'self'"])
        .worker_src(["'self'"])
        .object_src(["'none'"])
        .base_uri(["'self'"])
        .form_action(["'self'"])
        .frame_ancestors(["'none'"])
}

/// Le micro sert aux notes vocales de la discussion en ligne ; tout le reste
/// (caméra, position, paiement, USB…) est coupé.
const PERMISSIONS_POLICY: &str = "accelerometer=(), autoplay=(), camera=(), \
display-capture=(), encrypted-media=(), geolocation=(), gyroscope=(), magnetometer=(), \
microphone=(self), midi=(), payment=(), picture-in-picture=(), screen-wake-lock=(), usb=(), \
xr-spatial-tracking=()";

/// Le bouclier complet : le préréglage de Paquets (qui lit l'adresse du client
/// dans `X-Forwarded-For` sur Heroku), resserré pour une messagerie chiffrée.
pub fn bouclier(site: &Site) -> Shield {
    let mut csrf = Csrf::new();
    for prefix in API_PREFIXES {
        csrf = csrf.exempt(prefix);
    }
    paquets::shield()
        .guard(
            AutoBan::new()
                .statuses([401, 403])
                .max_strikes(20)
                .window(Duration::from_secs(60))
                .ban_for(Duration::from_secs(15 * 60)),
        )
        .guard(HttpsRedirect::new())
        .guard(BodyLimit::new(SMALL_BODY_LIMIT).route("/v1/messages", BODY_LIMIT as u64))
        // Contre l'inondation seulement : les plafonds par usage (salon, envoi,
        // Apple…) sont comptés par appareil dans `limits`, plus large par
        // adresse pour ne pas punir toute une box ou tout un bureau.
        .guard(RateLimit::new(Quota::per_second(50).burst(200)))
        .guard(ConcurrencyLimit::per_ip(128))
        .guard(Waf::new().paranoia(Paranoia::Medium))
        .guard(csrf)
        // Le site n'envoie aucun formulaire : tout corps reçu est du JSON.
        .guard(ContentTypeGuard::json())
        .guard(
            SecurityHeaders::new()
                .content_security_policy(content_security_policy(site))
                .permissions_policy(PERMISSIONS_POLICY),
        )
        .build()
}

/// Le bouclier, gardé dans l'état de l'application pour `/stats`.
#[derive(Clone)]
pub struct Bouclier(pub Shield);
