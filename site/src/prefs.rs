//! Préférences de l'utilisateur (langue, thème), partagées par contexte Yew et
//! mémorisées dans le localStorage — mêmes clés et mêmes valeurs que l'ancienne
//! vitrine, pour ne rien perdre.

use std::rc::Rc;

use yew::prelude::*;

use crate::i18n::Lang;

const LANG_KEY: &str = "messagerie.lang";
const THEME_KEY: &str = "messagerie.theme";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Theme {
    Green,
    Light,
    Dark,
}

impl Theme {
    pub const ALL: [Theme; 3] = [Theme::Green, Theme::Light, Theme::Dark];

    pub fn code(self) -> &'static str {
        match self {
            Theme::Green => "green",
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }

    pub fn from_code(code: &str) -> Option<Theme> {
        Theme::ALL.into_iter().find(|t| t.code() == code)
    }

    pub fn icon(self) -> &'static str {
        match self {
            Theme::Green => "🥦",
            Theme::Light => "☀️",
            Theme::Dark => "🌙",
        }
    }

    pub fn label_key(self) -> &'static str {
        match self {
            Theme::Green => "theme.green",
            Theme::Light => "theme.light",
            Theme::Dark => "theme.dark",
        }
    }

    /// Couleur de la barre du navigateur (meta theme-color).
    pub fn bar_color(self) -> &'static str {
        match self {
            Theme::Green => "#e9f4ec",
            Theme::Light => "#ffffff",
            Theme::Dark => "#0b110d",
        }
    }
}

fn storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok()?
}

fn load(key: &str) -> Option<String> {
    storage()?.get_item(key).ok()?
}

fn save(key: &str, value: &str) {
    if let Some(s) = storage() {
        let _ = s.set_item(key, value);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Prefs {
    pub lang: Lang,
    pub theme: Theme,
}

impl Prefs {
    pub fn load() -> Self {
        let lang = load(LANG_KEY)
            .as_deref()
            .and_then(Lang::from_code)
            .or_else(|| {
                web_sys::window()
                    .and_then(|w| w.navigator().language())
                    .as_deref()
                    .and_then(Lang::from_code)
            })
            .unwrap_or(Lang::Fr);
        let theme = load(THEME_KEY)
            .as_deref()
            .and_then(Theme::from_code)
            .unwrap_or(Theme::Green);
        Prefs { lang, theme }
    }

    pub fn t(&self, key: &str) -> &'static str {
        self.lang.t(key)
    }
}

pub enum PrefsAction {
    SetLang(Lang),
    SetTheme(Theme),
}

impl Reducible for Prefs {
    type Action = PrefsAction;

    fn reduce(self: Rc<Self>, action: PrefsAction) -> Rc<Self> {
        let mut next = (*self).clone();
        match action {
            PrefsAction::SetLang(lang) => {
                save(LANG_KEY, lang.code());
                next.lang = lang;
            }
            PrefsAction::SetTheme(theme) => {
                save(THEME_KEY, theme.code());
                next.theme = theme;
            }
        }
        Rc::new(next)
    }
}

pub type PrefsHandle = UseReducerHandle<Prefs>;

#[hook]
pub fn use_prefs() -> PrefsHandle {
    use_context::<PrefsHandle>().expect("PrefsHandle fourni par <App>")
}

/// Applique les préférences au document : thème, langue, titre et balises meta.
pub fn apply_to_document(prefs: &Prefs) {
    let doc = gloo::utils::document();
    if let Some(root) = doc.document_element() {
        let _ = root.set_attribute("data-theme", prefs.theme.code());
        let _ = root.set_attribute("lang", prefs.lang.code());
    }
    doc.set_title(prefs.t("meta.title"));
    let set_meta = |selector: &str, value: &str| {
        if let Ok(Some(el)) = doc.query_selector(selector) {
            let _ = el.set_attribute("content", value);
        }
    };
    set_meta(r#"meta[name="description"]"#, prefs.t("meta.desc"));
    set_meta(r#"meta[property="og:title"]"#, prefs.t("meta.ogTitle"));
    set_meta(r#"meta[property="og:description"]"#, prefs.t("meta.ogDesc"));
    set_meta(r#"meta[name="theme-color"]"#, prefs.theme.bar_color());
}
