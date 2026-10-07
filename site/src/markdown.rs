//! Rendu du README (Markdown → HTML) avec pulldown-cmark.
//!
//! - Les liens relatifs (LICENSE, site/, docs/…) pointent vers le dépôt GitHub,
//!   les images relatives vers leur version brute.
//! - Les liens externes s'ouvrent dans un nouvel onglet.
//! - Le HTML brut du Markdown est affiché comme du texte (jamais interprété).

use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd, html};

use crate::config::REPO_URL;

const RAW_URL: &str = "https://raw.githubusercontent.com/maxlestage/Messagerie-/master";

fn is_absolute(href: &str) -> bool {
    let lower = href.to_ascii_lowercase();
    lower.starts_with("http:") || lower.starts_with("https:") || lower.starts_with("mailto:")
}

fn strip_dot_slash(href: &str) -> &str {
    href.trim_start_matches("./").trim_start_matches('/')
}

/// Lien du README → URL finale. Les ancres et liens absolus restent tels quels.
pub fn resolve_href(href: &str) -> String {
    if href.is_empty() {
        return "#".into();
    }
    if href.starts_with('#') || is_absolute(href) {
        return href.into();
    }
    let kind = if href.ends_with('/') { "tree" } else { "blob" };
    format!("{REPO_URL}/{kind}/master/{}", strip_dot_slash(href))
}

/// Source d'image du README → URL finale (fichier brut du dépôt si relatif).
pub fn resolve_src(src: &str) -> String {
    if is_absolute(src) || src.starts_with("data:") {
        src.into()
    } else {
        format!("{RAW_URL}/{}", strip_dot_slash(src))
    }
}

fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

pub fn render(markdown: &str) -> String {
    let options = Options::ENABLE_TABLES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_FOOTNOTES
        | Options::ENABLE_GFM;

    // Pour chaque lien ouvert : true si on l'a réécrit en HTML (lien externe),
    // afin de fermer avec la bonne balise.
    let mut rewritten: Vec<bool> = Vec::new();

    let events = Parser::new_ext(markdown, options).map(|event| match event {
        Event::Start(Tag::Link {
            link_type,
            dest_url,
            title,
            id,
        }) => {
            let url = resolve_href(&dest_url);
            if url.starts_with("http") {
                rewritten.push(true);
                let title = if title.is_empty() {
                    String::new()
                } else {
                    format!(r#" title="{}""#, escape_attr(&title))
                };
                Event::InlineHtml(
                    format!(
                        r#"<a href="{}"{title} target="_blank" rel="noopener noreferrer">"#,
                        escape_attr(&url)
                    )
                    .into(),
                )
            } else {
                rewritten.push(false);
                Event::Start(Tag::Link {
                    link_type,
                    dest_url: url.into(),
                    title,
                    id,
                })
            }
        }
        Event::End(TagEnd::Link) => {
            if rewritten.pop() == Some(true) {
                Event::InlineHtml("</a>".into())
            } else {
                Event::End(TagEnd::Link)
            }
        }
        Event::Start(Tag::Image {
            link_type,
            dest_url,
            title,
            id,
        }) => Event::Start(Tag::Image {
            link_type,
            dest_url: resolve_src(&dest_url).into(),
            title,
            id,
        }),
        Event::Html(raw) | Event::InlineHtml(raw) => Event::Text(raw),
        other => other,
    });

    let mut out = String::with_capacity(markdown.len() * 3 / 2);
    html::push_html(&mut out, events);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_links_point_to_the_repo() {
        assert_eq!(
            resolve_href("LICENSE"),
            "https://github.com/maxlestage/Messagerie-/blob/master/LICENSE"
        );
        assert_eq!(
            resolve_href("./site/"),
            "https://github.com/maxlestage/Messagerie-/tree/master/site/"
        );
        assert_eq!(resolve_href("#install"), "#install");
        assert_eq!(resolve_href("mailto:a@b.c"), "mailto:a@b.c");
        assert_eq!(resolve_href(""), "#");
    }

    #[test]
    fn external_links_open_in_a_new_tab() {
        let html =
            render("[brocolis](https://maxlestage.github.io/brocolis/) et <https://example.com>");
        assert!(html.contains(r#"<a href="https://maxlestage.github.io/brocolis/" target="_blank" rel="noopener noreferrer">brocolis</a>"#));
        assert!(html.contains(r#"<a href="https://example.com" target="_blank""#));
    }

    #[test]
    fn relative_links_are_rewritten() {
        let html = render("Voir [la licence](LICENSE).");
        assert!(html.contains("https://github.com/maxlestage/Messagerie-/blob/master/LICENSE"));
        assert!(html.contains(r#"target="_blank""#));
    }

    #[test]
    fn anchors_stay_in_page() {
        let html = render("[haut](#top)");
        assert!(html.contains(r##"<a href="#top">haut</a>"##));
    }

    #[test]
    fn raw_html_is_escaped() {
        let html = render("<script>alert(1)</script>\n\nok <b>gras</b>");
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<b>"));
    }

    #[test]
    fn attributes_are_escaped() {
        let html = render(r#"[x](https://e.com/?a="b"&c)"#);
        assert!(html.contains("https://e.com/?a=&quot;b&quot;&amp;c"));
    }

    #[test]
    fn tables_and_images() {
        let html = render("| a | b |\n|---|---|\n| 1 | 2 |\n\n![logo](site/public/photo.png)");
        assert!(html.contains("<table>"));
        assert!(html.contains(
            "https://raw.githubusercontent.com/maxlestage/Messagerie-/master/site/public/photo.png"
        ));
    }
}
