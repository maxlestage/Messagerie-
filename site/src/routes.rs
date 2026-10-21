//! Les adresses du site : `/{langue}/`, `/{langue}/discuter/`, `/{langue}/salon/`,
//! `/{langue}/serveur/`, `/{langue}/licence/`, `/{langue}/protocole/`.

use crate::i18n::Lang;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Home,
    Chat,
    Salon,
    Server,
    License,
    Protocol,
    NotFound,
}

impl Page {
    /// Les pages qui ont une adresse.
    pub const ALL: [Page; 6] = [
        Page::Home,
        Page::Chat,
        Page::Salon,
        Page::Server,
        Page::License,
        Page::Protocol,
    ];

    fn slug(self) -> &'static str {
        match self {
            Page::Home => "",
            Page::Chat => "discuter",
            Page::Salon => "salon",
            Page::Server => "serveur",
            Page::License => "licence",
            Page::Protocol => "protocole",
            Page::NotFound => "404",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub lang: Lang,
    pub page: Page,
}

impl Route {
    pub fn new(lang: Lang, page: Page) -> Route {
        Route { lang, page }
    }

    /// La page d'une adresse ; `None` si elle ne commence pas par une langue.
    pub fn parse(path: &str) -> Option<Route> {
        let mut parts = path.split('/').filter(|p| !p.is_empty());
        let lang = Lang::parse(parts.next()?)?;
        let page = match (parts.next(), parts.next()) {
            (None, _) => Page::Home,
            // `/en/chat/` mène aussi à la discussion, `/en/protocol/` au protocole.
            (Some("chat"), None) => Page::Chat,
            (Some("protocol" | "protocolo"), None) => Page::Protocol,
            (Some(slug), None) => Page::ALL
                .into_iter()
                .find(|p| p.slug() == slug && *p != Page::Home)
                .unwrap_or(Page::NotFound),
            _ => Page::NotFound,
        };
        Some(Route { lang, page })
    }

    /// L'adresse de la page, toujours avec une barre finale.
    pub fn path(&self) -> String {
        match self.page {
            Page::Home => format!("/{}/", self.lang.code()),
            page => format!("/{}/{}/", self.lang.code(), page.slug()),
        }
    }

    /// La même page dans une autre langue.
    pub fn with_lang(&self, lang: Lang) -> Route {
        Route { lang, ..*self }
    }

    /// Toutes les pages, dans toutes les langues (plan du site).
    pub fn all() -> Vec<Route> {
        Lang::ALL
            .into_iter()
            .flat_map(|l| Page::ALL.into_iter().map(move |p| Route::new(l, p)))
            .collect()
    }
}

/// L'accueil d'une langue, avec une ancre éventuelle.
pub fn home(lang: Lang, anchor: &str) -> String {
    let home = Route::new(lang, Page::Home).path();
    if anchor.is_empty() {
        home
    } else {
        format!("{home}#{anchor}")
    }
}

/// L'adresse d'une ancre de l'ancien site (une seule page en `#/…`) :
/// `#/salon` → la page Salon, `#/pricing` → l'ancre des formules.
pub fn legacy_hash(lang: Lang, hash: &str) -> Option<String> {
    let rest = hash.trim_start_matches('#').strip_prefix('/')?;
    let page = |p| Route::new(lang, p).path();
    Some(match rest.trim_end_matches('/') {
        "salon" => page(Page::Salon),
        "serveur" => page(Page::Server),
        "license" | "licence" => page(Page::License),
        "protocole" | "protocol" => page(Page::Protocol),
        "features" | "pricing" | "doc" => home(lang, rest),
        _ => home(lang, ""),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_builds_urls() {
        let salon = Route::parse("/fr/salon/").unwrap();
        assert_eq!(salon, Route::new(Lang::Fr, Page::Salon));
        assert_eq!(salon.path(), "/fr/salon/");
        assert_eq!(salon.with_lang(Lang::Es).path(), "/es/salon/");
        assert_eq!(Route::parse("/en").unwrap().page, Page::Home);
        assert_eq!(Route::parse("/en/").unwrap().page, Page::Home);
        assert_eq!(Route::parse("/es/serveur").unwrap().page, Page::Server);
        assert_eq!(Route::parse("/es/licence").unwrap().page, Page::License);
        assert_eq!(Route::parse("/fr/discuter/").unwrap().page, Page::Chat);
        assert_eq!(Route::parse("/en/chat").unwrap().page, Page::Chat);
        assert_eq!(Route::new(Lang::Es, Page::Chat).path(), "/es/discuter/");
        assert_eq!(Route::parse("/fr/protocole/").unwrap().page, Page::Protocol);
        assert_eq!(Route::parse("/en/protocol").unwrap().page, Page::Protocol);
        assert_eq!(Route::parse("/en/nope/").unwrap().page, Page::NotFound);
        assert_eq!(Route::parse("/en/salon/x").unwrap().page, Page::NotFound);
        assert_eq!(Route::parse("/de/"), None);
        assert_eq!(Route::parse("/"), None);
    }

    #[test]
    fn lists_every_page_once() {
        let all = Route::all();
        assert_eq!(all.len(), 3 * 6);
        let mut paths: Vec<String> = all.iter().map(Route::path).collect();
        paths.sort();
        paths.dedup();
        assert_eq!(paths.len(), all.len());
    }

    #[test]
    fn translates_the_old_hash_urls() {
        assert_eq!(
            legacy_hash(Lang::Fr, "#/salon").as_deref(),
            Some("/fr/salon/")
        );
        assert_eq!(
            legacy_hash(Lang::En, "#/license").as_deref(),
            Some("/en/licence/")
        );
        assert_eq!(
            legacy_hash(Lang::Es, "#/pricing").as_deref(),
            Some("/es/#pricing")
        );
        assert_eq!(legacy_hash(Lang::Fr, "#/").as_deref(), Some("/fr/"));
        assert_eq!(legacy_hash(Lang::Fr, "#features"), None);
        assert_eq!(legacy_hash(Lang::Fr, ""), None);
    }
}
