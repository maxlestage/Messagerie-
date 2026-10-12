//! Le site côté serveur : ses routes, ajoutées à l'application Vitesse du
//! serveur Brocolis (à côté de l'API), et le rendu de ses pages avec Active.

pub mod markdown;
pub mod pages;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use vitesse::prelude::*;

use crate::i18n::Lang;
use crate::routes::{Page, Route};
use crate::{INTRO_COOKIE, LANG_COOKIE, THEME_COOKIE};

/// Le README du dépôt, embarqué à la compilation.
pub const README: &str = include_str!("../../../README.md");

/// Le dossier `site/` : `SITE_DIR`, sinon le dossier courant s'il contient
/// `assets/`, sinon celui de la crate.
pub fn site_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("SITE_DIR") {
        return PathBuf::from(dir);
    }
    if Path::new("assets/style.css").is_file() {
        return PathBuf::from(".");
    }
    if Path::new("site/assets/style.css").is_file() {
        return PathBuf::from("site");
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// FNV-1a, assez pour distinguer deux versions d'un fichier.
pub fn version(bytes: &[u8]) -> String {
    let h = bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    });
    format!("{h:016x}")[..10].to_owned()
}

/// L'empreinte de chaque fichier statique, pour les liens `?v=` (gardés en
/// cache pour toujours par les navigateurs).
#[derive(Default)]
pub struct Assets {
    files: BTreeMap<String, String>,
}

impl Assets {
    /// Les fichiers de `dir`, récursivement, sous le préfixe d'adresse `prefix`.
    pub fn load(&mut self, dir: &Path, prefix: &str) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            if path.is_dir() {
                self.load(&path, &format!("{prefix}/{name}"));
            } else if let Ok(bytes) = std::fs::read(&path) {
                self.files
                    .insert(format!("{prefix}/{name}"), version(&bytes));
            }
        }
    }

    /// `url?v=<empreinte>` si le fichier existe, `url` sinon.
    pub fn url(&self, url: &str) -> String {
        match self.files.get(url) {
            Some(hash) => format!("{url}?v={hash}"),
            None => url.to_owned(),
        }
    }

    pub fn has(&self, url: &str) -> bool {
        self.files.contains_key(url)
    }
}

/// Ce que le site prépare une fois au démarrage.
pub struct Site {
    pub dir: PathBuf,
    pub assets: Assets,
    /// Le README, déjà en HTML.
    pub readme: String,
    /// L'adresse publique (`SITE_URL`) ; `None` : celle de chaque requête.
    pub site_url: Option<String>,
}

impl Site {
    pub fn load() -> Site {
        let dir = site_dir();
        let mut assets = Assets::default();
        assets.load(&dir.join("assets"), "/assets");
        assets.load(&dir.join("pkg"), "/pkg");
        Site {
            dir,
            assets,
            readme: markdown::render(README),
            site_url: std::env::var("SITE_URL")
                .ok()
                .map(|u| u.trim().trim_end_matches('/').to_owned())
                .filter(|u| !u.is_empty()),
        }
    }

    /// Le code du navigateur a-t-il été construit (`site/pkg`) ?
    pub fn has_bundle(&self) -> bool {
        self.assets.has("/pkg/brocolis_site_bg.wasm")
    }

    /// L'adresse publique du site (`https://…`, sans barre finale).
    pub fn origin(&self, req: &Request) -> String {
        if let Some(url) = &self.site_url {
            return url.clone();
        }
        let header = |name: &str| {
            req.header(name)
                .map(|v| v.split(',').next().unwrap_or("").trim().to_owned())
        };
        let host = header("x-forwarded-host")
            .or_else(|| header("host"))
            .unwrap_or_default();
        if host.is_empty()
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
        {
            return "http://localhost".to_owned();
        }
        let proto = if header("x-forwarded-proto").as_deref() == Some("https") {
            "https"
        } else {
            "http"
        };
        format!("{proto}://{host}")
    }
}

/// Ce dont une page a besoin pour se rendre.
pub struct Ctx<'a> {
    pub site: &'a Site,
    pub route: Route,
    pub origin: String,
    /// Le thème choisi (cookie), `green` par défaut.
    pub theme: &'static str,
    /// Le rideau d'ouverture joue (première page de la visite).
    pub intro: bool,
}

impl Ctx<'_> {
    pub fn lang(&self) -> Lang {
        self.route.lang
    }

    pub fn t(&self, key: &str) -> &'static str {
        self.route.lang.t(key)
    }
}

/// La langue d'une requête : celle choisie dans le sélecteur, sinon celle du
/// navigateur.
fn preferred_lang(req: &Request) -> Lang {
    req.cookie(LANG_COOKIE)
        .and_then(Lang::parse)
        .unwrap_or_else(|| Lang::pick(req.header("accept-language").unwrap_or("")))
}

fn theme_of(req: &Request) -> &'static str {
    req.cookie(THEME_COOKIE)
        .and_then(crate::theme)
        .unwrap_or("green")
}

fn html(status: u16, html: String) -> Response {
    res::status(status)
        .header("cache-control", "no-cache")
        .header("vary", "Cookie")
        .html(html)
}

/// `/` : l'accueil de la langue choisie ou de celle du navigateur. Le
/// navigateur garde l'ancre (`/#/salon` de l'ancien site), que la page
/// d'accueil traduit.
fn root(_site: &Site, req: &Request) -> Response {
    let lang = preferred_lang(req);
    Redirect::to(format!("/{}/", lang.code()))
        .into_response()
        .header("vary", "Accept-Language, Cookie")
        .header("cache-control", "no-cache")
}

/// `/site/…` : l'ancienne adresse de la vitrine.
fn legacy(_site: &Site, _req: &Request) -> Response {
    Redirect::permanent("/").into_response()
}

/// Une page : `/{lang}/`, `/{lang}/salon/`, `/{lang}/serveur/`, `/{lang}/licence/`.
fn page(site: &Site, req: &Request) -> Response {
    let path = req.path();
    let Some(route) = Route::parse(path) else {
        return not_found(site, req);
    };
    if route.page == Page::NotFound {
        return not_found(site, req);
    }
    if !path.ends_with('/') {
        let query = req
            .query_string()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();
        return Redirect::permanent(format!("{path}/{query}")).into_response();
    }
    // Le rideau d'ouverture joue sur le premier accueil de la visite.
    let intro = route.page == Page::Home && req.cookie(INTRO_COOKIE).is_none();
    let body = pages::render(&Ctx {
        site,
        route,
        origin: site.origin(req),
        theme: theme_of(req),
        intro,
    });
    let response = html(200, body);
    if intro {
        response.header(
            "set-cookie",
            format!("{INTRO_COOKIE}=1; Path=/; SameSite=Lax"),
        )
    } else {
        response
    }
}

/// La page « introuvable », dans la langue de l'adresse ou du navigateur.
pub fn not_found(site: &Site, req: &Request) -> Response {
    let lang = Route::parse(req.path()).map_or_else(|| preferred_lang(req), |r| r.lang);
    let body = pages::render(&Ctx {
        site,
        route: Route::new(lang, Page::NotFound),
        origin: site.origin(req),
        theme: theme_of(req),
        intro: false,
    });
    html(404, body)
}

fn sitemap(site: &Site, req: &Request) -> Response {
    let origin = site.origin(req);
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\" xmlns:xhtml=\"http://www.w3.org/1999/xhtml\">\n",
    );
    for route in Route::all() {
        xml.push_str(&format!("<url><loc>{origin}{}</loc>", route.path()));
        for lang in Lang::ALL {
            xml.push_str(&format!(
                r#"<xhtml:link rel="alternate" hreflang="{}" href="{origin}{}"/>"#,
                lang.code(),
                route.with_lang(lang).path()
            ));
        }
        xml.push_str("</url>\n");
    }
    xml.push_str("</urlset>\n");
    res::send(xml).header("content-type", "application/xml; charset=utf-8")
}

fn robots(site: &Site, req: &Request) -> Response {
    let origin = site.origin(req);
    res::text(format!(
        "User-agent: *\nAllow: /\nDisallow: /v1/\nDisallow: /pair\nDisallow: /wrap\n\nSitemap: {origin}/sitemap.xml\n"
    ))
}

/// `/{lang}/manifest.webmanifest` : de quoi installer le site sur l'écran
/// d'accueil.
fn manifest(_site: &Site, req: &Request) -> Response {
    let lang = req.param("lang").and_then(Lang::parse).unwrap_or(Lang::Fr);
    res::send(pages::manifest(lang).to_json())
        .header("content-type", "application/manifest+json")
        .header("cache-control", "no-cache")
}

/// Route un gestionnaire qui n'a besoin que du site et de la requête.
fn route(app: &mut App, path: &str, site: &Arc<Site>, handler: fn(&Site, &Request) -> Response) {
    let site = site.clone();
    app.get(path, move |req: Request| {
        let site = site.clone();
        async move { handler(&site, &req) }
    });
}

/// Les fichiers dont l'adresse porte une empreinte (`?v=…`) ne changent
/// jamais : les navigateurs les gardent un an.
fn immutable(req: Request, next: Next) -> impl std::future::Future<Output = Response> + Send {
    let versioned = req.query_string().is_some_and(|q| q.starts_with("v="))
        && (req.path().starts_with("/assets/") || req.path().starts_with("/pkg/"));
    async move {
        let mut res = next.run(req).await;
        if versioned && res.status_code() == StatusCode::OK {
            res.set_header("cache-control", "public, max-age=31536000, immutable");
        }
        res
    }
}

/// Ajoute les routes du site à `app` (la page 404 reste à brancher par
/// l'appelant, voir [`not_found`]).
pub fn configure(app: &mut App, site: Arc<Site>) {
    app.middleware(immutable);
    route(app, "/", &site, root);
    route(app, "/site", &site, legacy);
    route(app, "/site/*rest", &site, legacy);
    route(app, "/:lang", &site, page);
    route(app, "/:lang/:page", &site, page);
    route(app, "/:lang/manifest.webmanifest", &site, manifest);
    route(app, "/sitemap.xml", &site, sitemap);
    route(app, "/robots.txt", &site, robots);
    let hour = Duration::from_secs(3600);
    app.serve_dir(
        "/assets",
        ServeDir::new(site.dir.join("assets")).max_age(hour),
    );
    app.serve_dir("/pkg", ServeDir::new(site.dir.join("pkg")).max_age(hour));
    // Le logo, à l'adresse qu'utilisaient les aperçus de liens de l'ancien site.
    for path in ["/photo.png", "/favicon.ico", "/apple-touch-icon.png"] {
        let icon = site.dir.join("assets/photo.png");
        app.get(path, move |_| {
            let icon = icon.clone();
            async move {
                res::file(icon)
                    .await
                    .header("cache-control", "public, max-age=86400")
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_change_with_the_content() {
        assert_eq!(version(b"a").len(), 10);
        assert_ne!(version(b"a"), version(b"b"));
    }

    #[test]
    fn the_readme_is_rendered() {
        let html = markdown::render(README);
        assert!(html.contains("<h1>"));
        assert!(!html.contains("<script"));
    }
}
