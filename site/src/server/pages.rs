//! Les pages, rendues avec Active : HTML complet, balises SEO comprises. Les
//! îlots (démo, salon, état du serveur) sont rendus ici puis hydratés dans le
//! navigateur ; le reste est du HTML statique que le code du navigateur anime.

use active::prelude::*;
use active::pwa::Manifest;

use super::Ctx;
use crate::i18n::{APPS, Lang};
use crate::islands::{chat_island, demo_island, salon_island, status_island};
use crate::routes::{self, Page, Route};
use crate::{BROCOLIS_URL, LICENSE_FILE, REPO_URL, STACK, THEMES};

const AUTHOR: &str = "Maxime Nathan Lestage";
const SITE_NAME: &str = "Brocolis 🥦 messageries";

/// Les fonctionnalités : (icône, titre, texte).
const FEATURES: [(&str, &str, &str); 8] = [
    ("🧩", "feat.graft.t", "feat.graft.d"),
    ("🔒", "feat.crypto.t", "feat.crypto.d"),
    ("🤝", "feat.pair.t", "feat.pair.d"),
    ("👥", "feat.group.t", "feat.group.d"),
    ("⏳", "feat.rotate.t", "feat.rotate.d"),
    ("⌚️", "feat.watch.t", "feat.watch.d"),
    ("📷", "feat.media.t", "feat.media.d"),
    ("🥦", "feat.interop.t", "feat.interop.d"),
];

const STATS: [(&str, &str); 3] = [
    ("stat.cipher", "stat.cipher.d"),
    ("stat.kex", "stat.kex.d"),
    ("stat.server", "stat.server.d"),
];

/// (préfixe de clé, emoji, mis en avant)
const PLANS: [(&str, &str, bool); 3] = [
    ("plan.free", "🌱", false),
    ("plan.plus", "🥦", false),
    ("plan.pro", "🚀", true),
];

/// Les phrases du film de grains (le dessin de chaque étape est dans le code
/// du navigateur).
pub const FILM: [&str; 6] = [
    "film.s0", "film.s1", "film.s2", "film.s3", "film.s4", "film.s5",
];

/// Les points d'accès présentés sur la page Serveur.
const ENDPOINTS: [(&str, &str, &str); 6] = [
    ("POST / GET", "/pair", "server.api.pair"),
    ("POST / GET", "/wrap", "server.api.wrap"),
    ("POST / GET", "/v1/messages", "server.api.messages"),
    ("GET", "/v1/stream", "server.api.stream"),
    ("GET", "/stats", "server.api.stats"),
    ("GET", "/health", "server.api.health"),
];

/// Ce qui défile dans le bandeau.
const MARQUEE: [&str; 10] = [
    "🔒 [[BROCOLIS:v1:…]]",
    "WhatsApp",
    "iMessage",
    "Messenger",
    "⌚ Apple Watch",
    "Notes",
    "X25519",
    "Signal",
    "AES-256-GCM",
    "Live Activity",
];

// ── Petits morceaux ───────────────────────────────────────────────────────────

fn external(href: &str) -> Element {
    a().href(href.to_owned())
        .attr("target", "_blank")
        .attr("rel", "noopener noreferrer")
}

/// Un titre découpé en mots qui montent l'un après l'autre (`.w` dans le CSS).
fn words(text: &str, start: usize) -> Vec<Node> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    let last = parts.len().saturating_sub(1);
    let mut out = Vec::new();
    for (i, w) in parts.into_iter().enumerate() {
        out.push(
            span()
                .class("w")
                .child(
                    span()
                        .style(format!("--i: {}", start + i))
                        .text(w.to_owned()),
                )
                .into(),
        );
        if i < last {
            out.push(Node::from(" "));
        }
    }
    out
}

/// L'en-tête d'une section : surtitre, titre, chapeau.
fn section_head(kicker: Option<&str>, id: &str, title: &str, note: &str) -> Element {
    div()
        .class("section-head reveal")
        .child(kicker.map(|k| p().class("kicker").text(k.to_owned())))
        .child(
            h2().id(id.to_owned())
                .attr("data-scramble", "")
                .text(title.to_owned()),
        )
        .child(p().text(note.to_owned()))
}

fn back(ctx: &Ctx<'_>) -> Element {
    p().child(
        a().class("back")
            .href(routes::home(ctx.lang(), ""))
            .text(ctx.t("back")),
    )
}

// ── Coquille : navigation, pied de page ───────────────────────────────────────

fn navbar(ctx: &Ctx<'_>) -> Element {
    let lang = ctx.lang();
    let current = ctx.route.page;
    let section = |anchor: &str, key: &str| {
        li().child(
            a().href(routes::home(lang, anchor))
                .attr("data-scramble", "")
                .text(ctx.t(key)),
        )
    };
    let page = |p: Page, key: &str| {
        li().child(
            a().href(Route::new(lang, p).path())
                .class(if current == p { "active" } else { "" })
                .attr("data-scramble", "")
                .text(ctx.t(key)),
        )
    };
    let outside = |href: &str, key: &str| {
        li().child(
            external(href)
                .text(ctx.t(key))
                .child(span().class("ext").attr("aria-hidden", "true").text("↗")),
        )
    };
    let langs = div()
        .class("switcher")
        .attr("role", "group")
        .attr("aria-label", ctx.t("switch.lang"))
        .children(Lang::ALL.into_iter().map(|l| {
            a().class("pill")
                .class(if l == lang { "active" } else { "" })
                .href(ctx.route.with_lang(l).path())
                .attr("hreflang", l.code())
                .attr("lang", l.code())
                .attr("data-lang", l.code())
                .text(l.code().to_uppercase())
        }));
    let themes = div()
        .class("switcher")
        .attr("role", "group")
        .attr("aria-label", ctx.t("switch.theme"))
        .children(THEMES.iter().map(|(code, icon, key)| {
            button()
                .class("pill")
                .class(if *code == ctx.theme { "active" } else { "" })
                .attr("type", "button")
                .attr("data-theme-set", *code)
                .attr("aria-pressed", (*code == ctx.theme).to_string())
                .attr("title", ctx.t(key))
                .attr("aria-label", ctx.t(key))
                .text(*icon)
        }));

    header().class("navbar").id("navbar").child(
        div()
            .class("nav-inner")
            .child(
                a().class("nav-brand")
                    .href(routes::home(lang, ""))
                    .child(
                        span()
                            .class("nav-leaf")
                            .attr("aria-hidden", "true")
                            .text("🥦"),
                    )
                    .child(span().text("Brocolis"))
                    .child(span().class("nav-brand-sub").text("messageries")),
            )
            .child(
                button()
                    .class("nav-toggle")
                    .attr("type", "button")
                    .attr("aria-label", ctx.t("nav.menu"))
                    .attr("aria-expanded", "false")
                    .attr("aria-controls", "nav-drawer")
                    .child(span())
                    .child(span())
                    .child(span()),
            )
            .child(
                div()
                    .class("nav-drawer")
                    .id("nav-drawer")
                    .child(
                        nav().attr("aria-label", ctx.t("nav.menu")).child(
                            ul().class("nav-links")
                                .child(section("features", "nav.features"))
                                .child(section("pricing", "nav.pricing"))
                                .child(section("doc", "nav.doc"))
                                .child(page(Page::Chat, "nav.chat"))
                                .child(page(Page::Salon, "nav.salon"))
                                .child(page(Page::Server, "nav.server"))
                                .child(outside(BROCOLIS_URL, "nav.brocolis"))
                                .child(outside(REPO_URL, "nav.github")),
                        ),
                    )
                    .child(div().class("switchers").child(langs).child(themes)),
            ),
    )
}

fn site_footer(ctx: &Ctx<'_>) -> Element {
    let lang = ctx.lang();
    footer().class("footer").child(
        div()
            .class("footer-inner")
            .child(
                div()
                    .class("footer-brand")
                    .child(
                        span()
                            .class("footer-leaf")
                            .attr("aria-hidden", "true")
                            .attr("data-burst", "")
                            .text("🥦"),
                    )
                    .child(p().class("footer-tagline").text(ctx.t("footer.tagline"))),
            )
            .child(
                nav()
                    .class("footer-links")
                    .attr("aria-label", ctx.t("nav.menu"))
                    .child(
                        a().href(Route::new(lang, Page::Chat).path())
                            .text(ctx.t("nav.chat")),
                    )
                    .child(
                        a().href(Route::new(lang, Page::Salon).path())
                            .text(ctx.t("nav.salon")),
                    )
                    .child(
                        a().href(Route::new(lang, Page::Server).path())
                            .text(ctx.t("nav.server")),
                    )
                    .child(
                        a().href(Route::new(lang, Page::License).path())
                            .text(ctx.t("nav.license")),
                    )
                    .child(external(REPO_URL).text(ctx.t("cta.repo")))
                    .child(external(BROCOLIS_URL).text("brocolis")),
            )
            .child(
                p().class("footer-meta")
                    .child(span().class("footer-credit").text(ctx.t("footer.credit")))
                    .child(span().class("footer-stack").text(ctx.t("footer.stack"))),
            ),
    )
}

/// Le rideau d'ouverture : la marque se trace, un compteur monte, puis le
/// rideau remonte (tout en CSS : il se lève même sans WebAssembly).
fn curtain() -> Element {
    div()
        .id("splash")
        .class("curtain")
        .attr("aria-hidden", "true")
        .child(
            svg()
                .class("curtain-mark")
                .attr("viewBox", "0 0 600 160")
                .child(
                    text_svg()
                        .attr("x", "300")
                        .attr("y", "80")
                        .attr("text-anchor", "middle")
                        .attr("dominant-baseline", "central")
                        .text("Brocolis"),
                ),
        )
        .child(
            div()
                .class("curtain-count")
                .child(span().class("curtain-n"))
                .child(i().text("%")),
        )
}

/// Une page complète autour de `content`.
fn layout(ctx: &Ctx<'_>, seo: Seo, content: Node) -> String {
    let site = ctx.site;
    let lang = ctx.lang();
    let body = fragment([
        Node::from(a().class("skip").href("#main").text(ctx.t("skip"))),
        ctx.intro.then(curtain).into(),
        div()
            .class("progress")
            .id("progress")
            .attr("aria-hidden", "true")
            .into(),
        div().class("grain").attr("aria-hidden", "true").into(),
        div().class("wipe").attr("aria-hidden", "true").into(),
        navbar(ctx).into(),
        el("main").id("main").class("page").child(content).into(),
        site_footer(ctx).into(),
        button()
            .class("to-top")
            .attr("type", "button")
            .attr("aria-label", ctx.t("top"))
            .attr("title", ctx.t("top"))
            .text("↑")
            .into(),
    ]);

    let origin = &ctx.origin;
    let mut seo = Seo::new()
        .site_name(SITE_NAME)
        .base_url(origin.clone())
        .image("/assets/photo.png")
        .meta_property("og:image:width", "640")
        .meta_property("og:image:height", "640")
        .meta_property("og:image:alt", ctx.t("meta.ogTitle"))
        .og_type("website")
        .locale(lang.og_locale())
        .merged(&seo);
    if ctx.route.page != Page::NotFound {
        seo = Lang::ALL
            .into_iter()
            .fold(seo.canonical(ctx.route.path()), |seo, l| {
                seo.alternate(l.code(), ctx.route.with_lang(l).path())
            })
            .alternate("x-default", ctx.route.with_lang(Lang::Fr).path());
    }

    let head = format!(
        concat!(
            r#"<meta name="color-scheme" content="light dark"/>"#,
            r#"<meta name="author" content="{author}"/>"#,
            r#"<link rel="icon" type="image/png" href="{icon}"/>"#,
        ),
        author = AUTHOR,
        icon = site.assets.url("/assets/photo.png"),
    );

    let mut doc = Document::new(body)
        .lang(lang.code())
        .viewport("width=device-width, initial-scale=1, viewport-fit=cover")
        .seo(seo)
        .stylesheet(site.assets.url("/assets/style.css"))
        .head(head)
        .manifest(
            &format!("/{}/manifest.webmanifest", lang.code()),
            &manifest(lang),
        )
        .html_attr("data-theme", ctx.theme)
        .html_attr("data-page", page_name(ctx.route.page));
    if ctx.intro {
        doc = doc.html_attr("class", "intro");
    }
    if site.has_bundle() {
        doc = doc.client(
            site.assets.url("/pkg/brocolis_site.js"),
            site.assets.url("/pkg/brocolis_site_bg.wasm"),
        );
    }
    doc.render()
}

fn page_name(page: Page) -> &'static str {
    match page {
        Page::Home => "home",
        Page::Chat => "chat",
        Page::Salon => "salon",
        Page::Server => "server",
        Page::License => "license",
        Page::NotFound => "404",
    }
}

/// Le manifeste de l'app installable.
pub fn manifest(lang: Lang) -> Manifest {
    Manifest::new(SITE_NAME)
        .short_name("Brocolis")
        .description(lang.t("meta.ogDesc"))
        .id("/")
        .start_url(format!("/{}/", lang.code()))
        .scope("/")
        .display("standalone")
        .theme_color("#2f9e4a")
        .background_color("#f2f8f3")
        .lang(lang.code())
        .icon("/assets/photo.png", "640x640", "image/png")
}

// ── Accueil ───────────────────────────────────────────────────────────────────

fn hero(ctx: &Ctx<'_>) -> Element {
    let lang = ctx.lang();
    let title = ctx.t("hero.title");
    let accent_start = title.split_whitespace().count();
    header()
        .class("hero")
        .id("top")
        .child(
            div()
                .class("hero-bg")
                .attr("aria-hidden", "true")
                .child(canvas().class("hero-rain"))
                .child(div().class("blob blob-a").attr("data-speed", "0.18"))
                .child(div().class("blob blob-b").attr("data-speed", "-0.12"))
                .child(div().class("blob blob-c").attr("data-speed", "0.08"))
                .child(div().class("hero-glow")),
        )
        .child(
            div()
                .class("hero-inner")
                .child(
                    span().class("logo-wrap").attr("data-burst", "").child(
                        img()
                            .class("logo-img")
                            .attr("src", ctx.site.assets.url("/assets/photo.png"))
                            .attr("alt", ctx.t("hero.alt"))
                            .attr("width", "148")
                            .attr("height", "148"),
                    ),
                )
                .child(
                    p().class("badge rise")
                        .style("--i: 0")
                        .text(ctx.t("hero.badge")),
                )
                .child(
                    h1().children(words(title, 0)).child(br()).child(
                        span()
                            .class("accent")
                            .children(words(ctx.t("hero.titleAccent"), accent_start)),
                    ),
                )
                .child(
                    p().class("tagline rise")
                        .style("--i: 5")
                        .text(ctx.t("hero.tagline"))
                        .child(external(BROCOLIS_URL).text("brocolis"))
                        .text("."),
                )
                .child(
                    p().class("works rise")
                        .style("--i: 6")
                        .child(span().text(ctx.t("works.label")))
                        .child(
                            span()
                                .class("rotator")
                                .attr("aria-label", APPS.join(", "))
                                .children(APPS.iter().enumerate().map(|(i, app)| {
                                    span()
                                        .class("rot-word")
                                        .attr("aria-hidden", "true")
                                        .style(format!("--k: {i}"))
                                        .text(*app)
                                })),
                        ),
                )
                .child(
                    div()
                        .class("cta rise")
                        .style("--i: 7")
                        .child(
                            a().class("btn primary")
                                .href(routes::home(lang, "pricing"))
                                .attr("data-burst", "")
                                .text(ctx.t("cta.pricing")),
                        )
                        .child(
                            a().class("btn")
                                .href(Route::new(lang, Page::Chat).path())
                                .attr("data-burst", "")
                                .text(ctx.t("cta.chat")),
                        )
                        .child(
                            a().class("btn")
                                .href(Route::new(lang, Page::Salon).path())
                                .text(ctx.t("cta.salon")),
                        )
                        .child(
                            a().class("btn")
                                .href(Route::new(lang, Page::Server).path())
                                .text(ctx.t("cta.server")),
                        )
                        .child(
                            external(REPO_URL)
                                .class("btn ghost")
                                .text(ctx.t("cta.repo")),
                        )
                        .child(
                            external(BROCOLIS_URL)
                                .class("btn ghost")
                                .text(ctx.t("cta.brocolis")),
                        ),
                )
                .child(
                    dl().class("stats rise")
                        .style("--i: 9")
                        .children(STATS.iter().map(|(v, d)| {
                            div()
                                .class("stat")
                                .child(dt().attr("data-scramble", "").text(ctx.t(v)))
                                .child(dd().text(ctx.t(d)))
                        })),
                ),
        )
        .child(
            a().class("scroll-cue")
                .href("#film")
                .attr("aria-label", ctx.t("film.hint"))
                .child(span()),
        )
}

fn marquee() -> Element {
    let track = |hidden: bool| {
        div()
            .class("marquee-group")
            .attr("aria-hidden", if hidden { "true" } else { "false" })
            .children(
                MARQUEE
                    .iter()
                    .map(|item| span().class("marquee-item").text(*item)),
            )
    };
    div().class("marquee").child(
        div()
            .class("marquee-track")
            .child(track(false))
            .child(track(true)),
    )
}

fn film(ctx: &Ctx<'_>) -> Element {
    section()
        .class("film")
        .id("film")
        .attr("aria-label", ctx.t("film.label"))
        .style(format!("--stations: {}", FILM.len()))
        .child(
            div()
                .class("film-stage")
                .child(canvas().class("film-canvas").attr("aria-hidden", "true"))
                .child(
                    div()
                        .class("film-fallback")
                        .attr("aria-hidden", "true")
                        .text("🥦"),
                )
                .child(
                    div()
                        .class("film-captions")
                        .children(FILM.iter().enumerate().map(|(i, key)| {
                            p().class("film-line")
                                .attr("data-station", i.to_string())
                                .text(ctx.t(key))
                        })),
                )
                .child(
                    p().class("film-count")
                        .attr("aria-hidden", "true")
                        .child(b().text("01"))
                        .child(span().text(format!(" / {:02}", FILM.len()))),
                )
                .child(
                    p().class("film-hint")
                        .attr("aria-hidden", "true")
                        .text(ctx.t("film.hint")),
                ),
        )
}

/// Deux téléphones, le salon au milieu : les clés publiques voyagent, la clé
/// secrète apparaît des deux côtés sans jamais passer par le fil.
fn flow(ctx: &Ctx<'_>) -> Element {
    let node = |class: &str, icon: &str, label: &str, key: bool| {
        div()
            .class("flow-node")
            .class(class.to_owned())
            .child(
                span()
                    .class("flow-icon")
                    .attr("aria-hidden", "true")
                    .text(icon.to_owned()),
            )
            .child(strong().text(label.to_owned()))
            .child(key.then(|| {
                span()
                    .class("flow-secret")
                    .attr("aria-hidden", "true")
                    .text("🔑")
            }))
    };
    let wire = |class: &str| {
        div()
            .class("flow-wire")
            .class(class.to_owned())
            .attr("aria-hidden", "true")
            .child(span().class("packet out").text("🔓"))
            .child(span().class("packet in").text("🔓"))
            .child(em().text(ctx.t("flow.pub")))
    };
    div()
        .class("flow reveal")
        .child(
            div()
                .class("flow-row")
                .child(node("flow-me", "📱", ctx.t("flow.me"), true))
                .child(wire("flow-wire-a"))
                .child(node("flow-server", "🛰️", ctx.t("flow.server"), false))
                .child(wire("flow-wire-b"))
                .child(node("flow-them", "📱", ctx.t("flow.them"), true)),
        )
        .child(
            p().class("flow-caption")
                .text("🔑 ")
                .text(ctx.t("flow.secret")),
        )
}

fn features(ctx: &Ctx<'_>) -> Element {
    section()
        .class("section")
        .id("features")
        .attr("aria-labelledby", "features-title")
        .child(section_head(
            None,
            "features-title",
            ctx.t("features.title"),
            ctx.t("features.note"),
        ))
        .child(
            div()
                .class("features")
                .children(FEATURES.iter().enumerate().map(|(i, (icon, title, text))| {
                    article()
                        .class("card reveal tilt")
                        .style(format!("--d: {}", i % 4))
                        .child(span().class("card-shine").attr("aria-hidden", "true"))
                        .child(
                            div()
                                .class("card-icon")
                                .attr("aria-hidden", "true")
                                .text(*icon),
                        )
                        .child(h3().text(ctx.t(title)))
                        .child(p().text(ctx.t(text)))
                })),
        )
}

fn pricing(ctx: &Ctx<'_>) -> Element {
    section()
        .class("section")
        .id("pricing")
        .attr("aria-labelledby", "pricing-title")
        .child(section_head(
            None,
            "pricing-title",
            ctx.t("pricing.title"),
            ctx.t("pricing.note"),
        ))
        .child(
            div().class("plans").children(PLANS.iter().enumerate().map(
                |(i, (prefix, icon, featured))| {
                    let k = |suffix: &str| ctx.t(&format!("{prefix}.{suffix}"));
                    let paid = *prefix != "plan.free";
                    article()
                        .class("plan reveal tilt")
                        .class(if *featured { "featured" } else { "" })
                        .style(format!("--d: {i}"))
                        .child(
                            featured
                                .then(|| span().class("plan-flag").text(ctx.t("pricing.popular"))),
                        )
                        .child(
                            h3().child(
                                span()
                                    .class("plan-icon")
                                    .attr("aria-hidden", "true")
                                    .text(*icon),
                            )
                            .text(" ")
                            .text(k("name")),
                        )
                        .child(
                            p().class("plan-price")
                                .child(strong().attr("data-count", "").text(k("price")))
                                .child(paid.then(|| span().text(ctx.t("pricing.month")))),
                        )
                        .child(ul().children(["f1", "f2", "f3"].iter().map(|f| li().text(k(f)))))
                },
            )),
        )
        .child(p().class("plans-foot reveal").text(ctx.t("pricing.foot")))
}

fn readme(ctx: &Ctx<'_>) -> Element {
    section()
        .class("section readme")
        .id("doc")
        .attr("aria-labelledby", "doc-title")
        .child(section_head(
            None,
            "doc-title",
            ctx.t("doc.title"),
            ctx.t("doc.note"),
        ))
        .child(
            div()
                .class("readme-box reveal")
                .id("readme")
                .child(
                    article()
                        .class("markdown")
                        .attr("lang", "fr")
                        .html(ctx.site.readme.clone()),
                )
                .child(div().class("readme-fade").attr("aria-hidden", "true")),
        )
        .child(
            p().class("readme-more").child(
                button()
                    .class("btn readme-toggle")
                    .attr("type", "button")
                    .attr("aria-controls", "readme")
                    .attr("aria-expanded", "false")
                    .attr("data-more", ctx.t("doc.more"))
                    .attr("data-less", ctx.t("doc.less"))
                    .text(ctx.t("doc.more")),
            ),
        )
}

fn home(ctx: &Ctx<'_>) -> String {
    let lang = ctx.lang();
    let content = fragment([
        Node::from(hero(ctx)),
        marquee().into(),
        film(ctx).into(),
        div()
            .class("container")
            .child(
                section()
                    .class("section")
                    .id("demo")
                    .attr("aria-labelledby", "demo-title")
                    .child(section_head(
                        Some(ctx.t("demo.kicker")),
                        "demo-title",
                        ctx.t("demo.title"),
                        ctx.t("demo.note"),
                    ))
                    .child(
                        div()
                            .class("reveal")
                            .child(island("demo", lang.code(), demo_island)),
                    ),
            )
            .child(
                section()
                    .class("section")
                    .id("flow")
                    .attr("aria-labelledby", "flow-title")
                    .child(section_head(
                        Some(ctx.t("flow.kicker")),
                        "flow-title",
                        ctx.t("flow.title"),
                        ctx.t("flow.note"),
                    ))
                    .child(flow(ctx)),
            )
            .child(features(ctx))
            .child(pricing(ctx))
            .child(readme(ctx))
            .into(),
    ]);
    let json_ld = format!(
        r#"{{"@context":"https://schema.org","@type":"SoftwareApplication","name":"Brocolis","operatingSystem":"iOS, watchOS, Android","applicationCategory":"CommunicationApplication","description":"{}","author":{{"@type":"Person","name":"{AUTHOR}"}},"offers":{{"@type":"Offer","price":"0","priceCurrency":"EUR"}}}}"#,
        json(ctx.t("meta.desc"))
    );
    let seo = Seo::new()
        .title(ctx.t("meta.title"))
        .description(ctx.t("meta.desc"))
        .json_ld(json_ld);
    layout(ctx, seo, content)
}

/// Une chaîne JSON (sans les guillemets).
fn json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '<' => out.push_str("\\u003c"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// ── Pages intérieures ─────────────────────────────────────────────────────────

fn inner(class: &str, title: &str, emoji: &str, children: Vec<Node>) -> Node {
    div()
        .class("container")
        .child(
            section()
                .class("legal")
                .class(class.to_owned())
                .child(
                    h1().children(words(title, 0)).text(" ").child(
                        span()
                            .class("title-emoji")
                            .attr("aria-hidden", "true")
                            .text(emoji.to_owned()),
                    ),
                )
                .children(children),
        )
        .into()
}

/// La discussion en ligne, seule sur sa page : on arrive, on invite ou on
/// rejoint, on discute.
fn chat(ctx: &Ctx<'_>) -> String {
    let content = inner(
        "chat-page",
        ctx.t("chat.title"),
        "💬",
        vec![
            p().class("lead rise")
                .style("--i: 3")
                .text(ctx.t("chat.intro"))
                .into(),
            div()
                .class("panel chat-panel rise")
                .style("--i: 4")
                .child(island("chat", ctx.lang().code(), chat_island))
                .into(),
            ol().class("steps")
                .children(["chat.step1", "chat.step2", "chat.step3"].iter().enumerate().map(|(i, s)| {
                    li().class("reveal")
                        .style(format!("--d: {i}"))
                        .text(ctx.t(s))
                }))
                .into(),
            p().class("callout reveal")
                .text("🔑 ")
                .text(ctx.t("salon.fingerprint"))
                .into(),
            p().class("legal-note")
                .text(ctx.t("chat.more"))
                .text(" ")
                .child(a().href(Route::new(ctx.lang(), Page::Salon).path()).text(ctx.t("nav.salon")))
                .into(),
            back(ctx).into(),
        ],
    );
    let seo = Seo::new()
        .title(format!("{} — Brocolis 🥦", ctx.t("chat.title")))
        .description(ctx.t("chat.intro"));
    layout(ctx, seo, content)
}

fn salon(ctx: &Ctx<'_>) -> String {
    let steps = ["salon.step1", "salon.step2", "salon.step3", "salon.step4"];
    let content = inner(
        "salon-page",
        ctx.t("salon.title"),
        "🤝",
        vec![
            p().class("lead rise")
                .style("--i: 3")
                .text(ctx.t("salon.intro"))
                .into(),
            // Discuter tout de suite, depuis le navigateur.
            h2().class("reveal")
                .id("discuter")
                .text(ctx.t("chat.title"))
                .into(),
            p().class("legal-note").text(ctx.t("chat.intro")).into(),
            div()
                .class("panel chat-panel reveal")
                .child(island("chat", ctx.lang().code(), chat_island))
                .into(),
            flow(ctx).into(),
            h2().class("reveal")
                .attr("data-scramble", "")
                .text(ctx.t("salon.howTitle"))
                .into(),
            ol().class("steps")
                .children(steps.iter().enumerate().map(|(i, s)| {
                    li().class("reveal")
                        .style(format!("--d: {i}"))
                        .text(ctx.t(s))
                }))
                .into(),
            p().class("callout reveal")
                .text("🔑 ")
                .text(ctx.t("salon.fingerprint"))
                .into(),
            h2().class("reveal")
                .attr("data-scramble", "")
                .text(ctx.t("salon.roomTitle"))
                .into(),
            p().class("legal-note").text(ctx.t("salon.roomNote")).into(),
            island("salon", ctx.lang().code(), salon_island),
            p().class("legal-note").text(ctx.t("salon.privacy")).into(),
            back(ctx).into(),
        ],
    );
    let seo = Seo::new()
        .title(format!("{} — Brocolis 🥦", ctx.t("salon.title")))
        .description(ctx.t("salon.intro"));
    layout(ctx, seo, content)
}

fn server(ctx: &Ctx<'_>) -> String {
    let content = inner(
        "server-page",
        ctx.t("server.title"),
        "🛰️",
        vec![
            p().class("lead rise")
                .style("--i: 3")
                .text(ctx.t("server.note"))
                .into(),
            island("status", ctx.lang().code(), status_island),
            p().class("callout reveal")
                .text("💾 ")
                .text(ctx.t("server.memory"))
                .into(),
            h2().class("reveal")
                .attr("data-scramble", "")
                .text(ctx.t("server.stack"))
                .into(),
            ul().class("stack")
                .children(
                    STACK
                        .iter()
                        .enumerate()
                        .map(|(i, (icon, name, href, key))| {
                            li().class("reveal tilt")
                                .style(format!("--d: {i}"))
                                .child(
                                    span()
                                        .class("stack-icon")
                                        .attr("aria-hidden", "true")
                                        .text(*icon),
                                )
                                .child(external(href).class("stack-name").text(*name))
                                .child(span().class("stack-text").text(ctx.t(key)))
                        }),
                )
                .into(),
            h2().class("reveal")
                .attr("data-scramble", "")
                .text(ctx.t("server.api"))
                .into(),
            ul().class("endpoints")
                .children(
                    ENDPOINTS
                        .iter()
                        .enumerate()
                        .map(|(i, (method, path, key))| {
                            li().class("reveal")
                                .style(format!("--d: {}", i % 4))
                                .child(code().class("method").text(*method))
                                .child(code().class("path").text(*path))
                                .child(span().text(ctx.t(key)))
                        }),
                )
                .into(),
            p().class("legal-note").text(ctx.t("server.privacy")).into(),
            back(ctx).into(),
        ],
    );
    let seo = Seo::new()
        .title(format!("{} — Brocolis 🥦", ctx.t("server.title")))
        .description(ctx.t("server.note"));
    layout(ctx, seo, content)
}

fn license(ctx: &Ctx<'_>) -> String {
    let content = inner(
        "license-page",
        ctx.t("license.title"),
        "📜",
        vec![
            p().class("legal-note").text(ctx.t("license.note")).into(),
            pre()
                .class("license-text reveal")
                .text(ctx.t("license.full"))
                .into(),
            p().child(external(LICENSE_FILE).text(ctx.t("license.viewFile")))
                .into(),
            back(ctx).into(),
        ],
    );
    let seo = Seo::new()
        .title(format!("{} — Brocolis 🥦", ctx.t("license.title")))
        .description(ctx.t("meta.desc"));
    layout(ctx, seo, content)
}

fn not_found(ctx: &Ctx<'_>) -> String {
    let content = div()
        .class("container")
        .child(
            section()
                .class("lost")
                .child(
                    p().class("lost-code")
                        .attr("data-scramble", "")
                        .attr("aria-hidden", "true")
                        .text("404"),
                )
                .child(h1().text(ctx.t("nf.title")))
                .child(p().class("lead").text(ctx.t("nf.text")))
                .child(
                    a().class("btn primary")
                        .href(routes::home(ctx.lang(), ""))
                        .attr("data-burst", "")
                        .text(ctx.t("back")),
                ),
        )
        .into();
    let seo = Seo::new()
        .title(format!("{} — Brocolis 🥦", ctx.t("nf.title")))
        .description(ctx.t("nf.text"))
        .noindex(true);
    layout(ctx, seo, content)
}

/// Rend la page de `ctx.route`.
pub fn render(ctx: &Ctx<'_>) -> String {
    match ctx.route.page {
        Page::Home => home(ctx),
        Page::Chat => chat(ctx),
        Page::Salon => salon(ctx),
        Page::Server => server(ctx),
        Page::License => license(ctx),
        Page::NotFound => not_found(ctx),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{Assets, Site};

    fn site() -> Site {
        Site {
            dir: std::path::PathBuf::from("."),
            assets: Assets::default(),
            readme: "<h1>README</h1>".into(),
            site_url: None,
        }
    }

    fn page(lang: Lang, page: Page, theme: &'static str, intro: bool) -> String {
        render(&Ctx {
            site: &site(),
            route: Route::new(lang, page),
            origin: "https://brocolis.example".into(),
            theme,
            intro,
        })
    }

    #[test]
    fn every_page_renders_in_every_language() {
        for route in Route::all() {
            let html = page(route.lang, route.page, "green", false);
            assert!(
                html.starts_with("<!DOCTYPE html>") || html.starts_with("<!doctype html>"),
                "{route:?}"
            );
            assert!(html.contains(&format!(r#"lang="{}""#, route.lang.code())));
            assert!(
                html.contains(&format!(
                    r#"<link rel="canonical" href="https://brocolis.example{}""#,
                    route.path()
                )),
                "{route:?}"
            );
            assert!(html.contains(r#"hreflang="es""#));
        }
    }

    #[test]
    fn the_home_page_has_its_islands_and_sections() {
        let html = page(Lang::Fr, Page::Home, "dark", true);
        assert!(html.contains(r#"data-theme="dark""#));
        assert!(html.contains(r#"class="intro""#));
        assert!(html.contains(r#"id="splash""#));
        for id in ["features", "pricing", "doc", "demo", "flow", "film"] {
            assert!(html.contains(&format!(r#"id="{id}""#)), "{id}");
        }
        assert!(html.contains(r#"data-island="demo""#));
        assert!(html.contains("<h1>README</h1>"));
        assert!(html.contains("application/ld+json"));
        // Sans code du navigateur construit, pas de script qui manquerait.
        assert!(!html.contains("/pkg/brocolis_site.js"));
    }

    #[test]
    fn inner_pages_carry_their_islands() {
        assert!(page(Lang::En, Page::Salon, "green", false).contains(r#"data-island="salon""#));
        assert!(page(Lang::Es, Page::Server, "green", false).contains(r#"data-island="status""#));
        let lost = page(Lang::Fr, Page::NotFound, "green", false);
        assert!(lost.contains("noindex"));
        assert!(!lost.contains(r#"rel="canonical""#));
    }

    #[test]
    fn json_strings_are_escaped() {
        assert_eq!(json(r#"a "b" \ </script>"#), r#"a \"b\" \\ \u003c/script>"#);
    }
}
