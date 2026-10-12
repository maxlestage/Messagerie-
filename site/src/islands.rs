//! Les îlots : les parties interactives du site. Chacun est rendu par le
//! serveur comme n'importe quelle vue (lisible sans JavaScript et par les
//! moteurs de recherche) puis, compilé en WebAssembly, hydraté dans le
//! navigateur à partir du même code. Le reste de la page est du HTML statique.

use active::prelude::*;

use crate::demo::{self, Segment};
use crate::i18n::Lang;

/// Tous les îlots, sous le nom donné à [`island`].
pub const ISLANDS: [(&str, active::IslandFn); 3] = [
    ("demo", demo_island),
    ("salon", salon_island),
    ("status", status_island),
];

/// Le sel des jetons factices : le même sur le serveur et dans le navigateur,
/// pour que l'hydratation retrouve exactement le HTML envoyé.
const SALT: u64 = 0xB20C_0115;

/// La langue des propriétés d'un îlot (`"fr"`…).
pub fn lang(props: &str) -> Lang {
    props.get(..2).and_then(Lang::parse).unwrap_or(Lang::Fr)
}

// ── Démo : ce que tu écris, ce que voit l'app ─────────────────────────────────

fn indexed_segments(text: &str, all: bool) -> Vec<(usize, Segment)> {
    demo::segments(text, all).into_iter().enumerate().collect()
}

/// Un message tapé en direct, à gauche en clair (secrets surlignés), à droite
/// tel qu'il part dans la messagerie (secrets brouillés en jetons).
pub fn demo_island(props: &str) -> Node {
    let lang = lang(props);
    let text = use_state(lang.t("demo.default").to_string());
    let all = use_state(false);
    let parts = memo(move || indexed_segments(&text.get(), all.get()));
    let count = move || {
        parts.with(|p| {
            p.iter()
                .filter(|(_, s)| matches!(s, Segment::Secret(_)))
                .count()
        })
    };

    let key = |(i, s): &(usize, Segment)| (*i, s.clone());
    div()
        .class("demo")
        .child(
            div()
                .class("demo-input")
                .child(label().attr("for", "demo-text").text(lang.t("demo.input")))
                .child(
                    textarea()
                        .id("demo-text")
                        .class("input demo-text")
                        .attr("rows", "3")
                        .attr("spellcheck", "false")
                        .on_input(move |e| text.set(e.value()))
                        .text(lang.t("demo.default")),
                )
                .child(
                    div()
                        .class("demo-tools")
                        .child(
                            button()
                                .class("toggle")
                                .attr("type", "button")
                                .attr_dyn("aria-pressed", move || all.get().to_string())
                                .on_click(move |_| all.update(|a| *a = !*a))
                                .child(span().class("toggle-knob").attr("aria-hidden", "true"))
                                .text(lang.t("demo.all")),
                        )
                        .child(
                            span()
                                .class("demo-count")
                                .child(b().text_dyn(move || count().to_string()))
                                .text(" ")
                                .text(lang.t("demo.tokens")),
                        ),
                ),
        )
        .child(
            div()
                .class("demo-panes")
                .child(
                    figure()
                        .class("pane pane-phone")
                        .child(figcaption().text("🔓 ").text(lang.t("demo.plain")))
                        .child(p().class("bubble bubble-me").children_keyed(
                            move || parts.get(),
                            key,
                            |(_, s)| match s {
                                Segment::Plain(t) => span().text(t.clone()).into(),
                                Segment::Secret(t) => mark().class("secret").text(t.clone()).into(),
                            },
                        )),
                )
                .child(
                    div()
                        .class("demo-flow")
                        .attr("aria-hidden", "true")
                        .child(span())
                        .child(span())
                        .child(span())
                        .child(em().text("AES-256-GCM")),
                )
                .child(
                    figure()
                        .class("pane pane-wire")
                        .child(figcaption().text("🔒 ").text(lang.t("demo.wire")))
                        .child(p().class("bubble bubble-wire").children_keyed(
                            move || parts.get(),
                            key,
                            |(_, s)| match s {
                                Segment::Plain(t) => span().text(t.clone()).into(),
                                Segment::Secret(t) => {
                                    let token = demo::fake_token(t, SALT);
                                    let _final = token.clone();
                                    code()
                                        .class("tok")
                                        .on_mount(move |_el| {
                                            // Le jeton se brouille avant de se poser.
                                            #[cfg(target_arch = "wasm32")]
                                            crate::client::motion::scramble(_el, &_final, 700.0);
                                        })
                                        .text(token)
                                        .into()
                                }
                            },
                        )),
                ),
        )
        .child(p().class("demo-note").text(lang.t("demo.disclaimer")))
        .into()
}

// ── Salon des rendez-vous, en direct ──────────────────────────────────────────

/// Un participant d'un salon : son identifiant et sa clé publique.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Peer {
    pub id: String,
    pub public_key: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Room {
    Loading,
    Peers(Vec<Peer>),
    Unreachable,
}

/// Les 14 premiers caractères d'une clé, suivis de « … ».
pub fn short_key(key: &str) -> String {
    let head: String = key.chars().take(14).collect();
    if head.len() < key.len() {
        format!("{head}…")
    } else {
        head
    }
}

/// Un visage pour une clé publique : une grille 5×5 symétrique et une teinte,
/// tirées de la clé (la même clé donne toujours le même visage).
pub fn identicon(key: &str) -> (u32, [bool; 25]) {
    let h = key.bytes().fold(0x811c_9dc5_u32, |h, b| {
        (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
    });
    let mut cells = [false; 25];
    for row in 0..5 {
        for col in 0..3 {
            let on = (h >> (row * 3 + col)) & 1 == 1;
            cells[row * 5 + col] = on;
            cells[row * 5 + 4 - col] = on;
        }
    }
    (h % 360, cells)
}

fn face(key: &str) -> Element {
    let (hue, cells) = identicon(key);
    span()
        .class("face")
        .attr("aria-hidden", "true")
        .style(format!("--h:{hue}"))
        .children(
            cells
                .iter()
                .map(|on| span().class(if *on { "on" } else { "" })),
        )
}

/// Saisis un code : les participants présents apparaissent, actualisés toutes
/// les quatre secondes (clés publiques seulement).
pub fn salon_island(props: &str) -> Node {
    let lang = lang(props);
    let typed = use_state(String::new());
    let active = use_state(None::<String>);
    let room = use_state(Room::Loading);
    let refreshing = use_state(false);

    let open = move |c: String| {
        if c.is_empty() {
            return;
        }
        if active.with(|a| a.as_deref() != Some(c.as_str())) {
            room.set(Room::Loading);
        }
        active.set(Some(c.clone()));
        #[cfg(target_arch = "wasm32")]
        crate::client::live::watch_room(c, room, refreshing);
    };

    let peers = move || match room.get() {
        Room::Peers(p) => p,
        _ => Vec::new(),
    };

    fragment([
        Node::from(
            form()
                .class("salon-form")
                .on("submit", move |e| {
                    e.prevent_default();
                    open(typed.get().trim().to_string());
                })
                .on_mount(move |_form| {
                    // Un lien partagé `?code=4813` ouvre directement le salon.
                    #[cfg(target_arch = "wasm32")]
                    if let Some(c) = active::query_param("code").filter(|c| !c.trim().is_empty()) {
                        typed.set(c.trim().to_string());
                        open(c.trim().to_string());
                    }
                })
                .child(
                    label()
                        .attr("for", "salon-code")
                        .text(lang.t("salon.codeLabel")),
                )
                .child(
                    div()
                        .class("salon-row")
                        .child(
                            input()
                                .id("salon-code")
                                .class("input")
                                .attr("inputmode", "text")
                                .attr("autocomplete", "off")
                                .attr("placeholder", lang.t("salon.codePlaceholder"))
                                .attr_dyn("value", move || typed.get())
                                .on_input(move |e| typed.set(e.value())),
                        )
                        .child(
                            button()
                                .class("btn primary")
                                .attr("type", "submit")
                                .bool_attr("disabled", move || typed.with(|c| c.trim().is_empty()))
                                .text(lang.t("salon.view")),
                        ),
                ),
        ),
        div()
            .class("panel salon-room")
            .class_if("is-open", move || active.with(Option::is_some))
            .attr("aria-live", "polite")
            .child(
                p().class("salon-room-head")
                    .child(strong().text(lang.t("salon.peers")))
                    .child(
                        code()
                            .class("code-badge")
                            .text_dyn(move || active.get().unwrap_or_default()),
                    )
                    .child(
                        span()
                            .class("live-pill")
                            .class_if("is-busy", move || refreshing.get())
                            .child(span().class("live-dot").attr("aria-hidden", "true"))
                            .text(lang.t("salon.live")),
                    )
                    .child(span().class("peer-count").text_dyn(move || {
                        let n = peers().len();
                        if n == 0 {
                            String::new()
                        } else {
                            format!("× {n}")
                        }
                    })),
            )
            .children_dyn(move || match room.get() {
                Room::Loading => vec![radar(lang.t("salon.waiting"))],
                Room::Peers(p) if p.is_empty() => vec![radar(lang.t("salon.empty"))],
                Room::Peers(_) => Vec::new(),
                Room::Unreachable => vec![
                    div()
                        .class("salon-error")
                        .child(strong().text(lang.t("salon.errorTitle")))
                        .child(p().text(lang.t("salon.errorCors")))
                        .into(),
                ],
            })
            .child(ul().class("salon-peers").children_keyed(
                peers,
                |p| p.id.clone(),
                move |p| {
                    li().class("peer")
                        .child(face(&p.public_key))
                        .child(
                            span()
                                .class("peer-text")
                                .child(span().class("salon-peer-id").text(p.id.clone()))
                                .child(
                                    code()
                                        .class("salon-peer-pub")
                                        .attr("title", p.public_key.clone())
                                        .text(format!(
                                            "{}: {}",
                                            lang.t("salon.pub"),
                                            short_key(&p.public_key)
                                        )),
                                ),
                        )
                        .into()
                },
            ))
            .into(),
    ])
}

/// Un radar qui balaie en attendant des participants.
fn radar(label: &'static str) -> Node {
    div()
        .class("radar-wrap")
        .child(
            span()
                .class("radar")
                .attr("aria-hidden", "true")
                .child(span().class("radar-sweep"))
                .child(span().class("radar-blip")),
        )
        .child(p().class("salon-empty").text(label))
        .into()
}

// ── État du serveur, en direct ───────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Status {
    Checking,
    Online(u32),
    Offline,
}

/// Les chiffres publics de `/stats`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Stats {
    pub messages: f64,
    pub conversations: f64,
    pub rooms: f64,
    pub listeners: f64,
    pub bytes: f64,
    pub uptime: f64,
}

/// Le nombre de barres du graphique de latence.
pub const BARS: usize = 24;

/// `1 234` / `1,234` selon la langue.
pub fn group(lang: Lang, n: f64) -> String {
    let digits = format!("{:.0}", n.max(0.0));
    let sep = match lang {
        Lang::En => ",",
        _ => "\u{202f}",
    };
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push_str(sep);
        }
        out.push(c);
    }
    out
}

/// Une taille en octets, lisible (`12,4 Ko`, `12.4 KB`).
pub fn bytes(lang: Lang, n: f64) -> String {
    let units: [&str; 4] = match lang {
        Lang::Fr => ["o", "Ko", "Mo", "Go"],
        _ => ["B", "KB", "MB", "GB"],
    };
    let mut v = n.max(0.0);
    let mut u = 0;
    while v >= 1024.0 && u < 3 {
        v /= 1024.0;
        u += 1;
    }
    let s = if u == 0 {
        format!("{v:.0}")
    } else {
        format!("{v:.1}")
    };
    let s = if lang == Lang::En {
        s
    } else {
        s.replace('.', ",")
    };
    format!("{s} {}", units[u])
}

/// Découpe `2,99 €` en (`""`, 2.99, 2 décimales, `,`, `" €"`).
pub fn parse_number(text: &str) -> Option<(String, f64, usize, char, String)> {
    let start = text.find(|c: char| c.is_ascii_digit())?;
    let rest = &text[start..];
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == ',' || c == '.'))
        .unwrap_or(rest.len());
    let raw = rest[..end].trim_end_matches([',', '.']);
    let sep = if raw.contains(',') { ',' } else { '.' };
    let decimals = raw.rsplit_once(sep).map_or(0, |(_, d)| d.len());
    let value: f64 = raw.replace(',', ".").parse().ok()?;
    Some((
        text[..start].to_owned(),
        value,
        decimals,
        sep,
        text[start + raw.len()..].to_owned(),
    ))
}

/// Une durée (`3 j 04:05:06`, `04:05:06`).
pub fn duration(lang: Lang, secs: f64) -> String {
    let s = secs.max(0.0) as u64;
    let (d, h, m, s) = (s / 86_400, s / 3600 % 24, s / 60 % 60, s % 60);
    let day = match lang {
        Lang::Fr => "j",
        _ => "d",
    };
    if d > 0 {
        format!("{d} {day} {h:02}:{m:02}:{s:02}")
    } else {
        format!("{h:02}:{m:02}:{s:02}")
    }
}

/// L'état du serveur qui sert la page : latence (vérifiée toutes les cinq
/// secondes, avec son graphique), et les chiffres publics qui défilent.
pub fn status_island(props: &str) -> Node {
    let lang = lang(props);
    let status = use_state(Status::Checking);
    let history = use_state(Vec::<u32>::new());
    // Les chiffres reçus, et ceux affichés (qui les rattrapent en défilant).
    let target = use_state(Stats::default());
    let shown = use_state(Stats::default());
    let origin = use_state(String::new());

    #[cfg(not(target_arch = "wasm32"))]
    let _ = target;
    let check = move || {
        #[cfg(target_arch = "wasm32")]
        crate::client::live::probe(status, history);
    };

    let tile =
        move |label: &'static str, value: fn(&Stats) -> f64, format: fn(Lang, f64) -> String| {
            div()
                .class("tile")
                .child(
                    b().class("tile-num")
                        .text_dyn(move || format(lang, shown.with(value))),
                )
                .child(span().class("tile-label").text(label))
        };

    div()
        .class("status")
        .on_mount(move |_root| {
            #[cfg(target_arch = "wasm32")]
            crate::client::live::start_status(status, history, target, shown, origin);
        })
        .child(
            div()
                .class("panel server-card")
                .child(
                    div()
                        .class("server-row")
                        .child(strong().text(lang.t("server.status")))
                        .child(
                            span()
                                .class("server-status")
                                .class_if("checking", move || status.get() == Status::Checking)
                                .class_if("online", move || {
                                    matches!(status.get(), Status::Online(_))
                                })
                                .class_if("offline", move || status.get() == Status::Offline)
                                .attr("role", "status")
                                .child(
                                    span()
                                        .class("server-dot")
                                        .attr("aria-hidden", "true")
                                        .child(span())
                                        .child(span()),
                                )
                                .text_dyn(move || {
                                    match status.get() {
                                        Status::Checking => lang.t("server.checking"),
                                        Status::Online(_) => lang.t("server.online"),
                                        Status::Offline => lang.t("server.offline"),
                                    }
                                    .to_string()
                                })
                                .child(em().text_dyn(move || match status.get() {
                                    Status::Online(ms) => {
                                        format!(" — {} {ms} ms", lang.t("server.latency"))
                                    }
                                    _ => String::new(),
                                })),
                        ),
                )
                .child(
                    div()
                        .class("server-row")
                        .child(strong().text(lang.t("server.address")))
                        .child(code().class("server-url").text_dyn(move || origin.get())),
                )
                .child(
                    div()
                        .class("spark")
                        .attr("role", "img")
                        .attr("aria-label", lang.t("server.chart"))
                        .children((0..BARS).map(|i| {
                            span().class("spark-bar").attr_dyn("style", move || {
                                history.with(|h| {
                                    // Les mesures s'alignent à droite, la plus récente au bout.
                                    let offset = BARS.saturating_sub(h.len());
                                    match i.checked_sub(offset).and_then(|k| h.get(k)) {
                                        Some(ms) => {
                                            let max = h.iter().copied().max().unwrap_or(1).max(40);
                                            format!("--v:{:.3}", f64::from(*ms) / f64::from(max))
                                        }
                                        None => "--v:0".to_string(),
                                    }
                                })
                            })
                        })),
                )
                .child(p().class("spark-label").text(lang.t("server.chart")))
                .child(
                    div()
                        .class("cta")
                        .child(
                            a().class("btn primary")
                                .attr_dyn("href", move || {
                                    let o = origin.get();
                                    if o.is_empty() { "/".to_string() } else { o }
                                })
                                .attr("target", "_blank")
                                .attr("rel", "noopener noreferrer")
                                .text(lang.t("server.open")),
                        )
                        .child(
                            button()
                                .class("btn")
                                .attr("type", "button")
                                .bool_attr("disabled", move || status.get() == Status::Checking)
                                .on_click(move |_| check())
                                .text(lang.t("server.recheck")),
                        ),
                ),
        )
        .child(
            div().class("tiles-head").child(
                span()
                    .class("live-pill")
                    .child(span().class("live-dot"))
                    .text(lang.t("server.live")),
            ),
        )
        .child(
            div()
                .class("tiles")
                .child(tile(lang.t("server.stat.messages"), |s| s.messages, group))
                .child(tile(
                    lang.t("server.stat.conversations"),
                    |s| s.conversations,
                    group,
                ))
                .child(tile(lang.t("server.stat.rooms"), |s| s.rooms, group))
                .child(tile(
                    lang.t("server.stat.listeners"),
                    |s| s.listeners,
                    group,
                ))
                .child(tile(lang.t("server.stat.bytes"), |s| s.bytes, bytes))
                .child(tile(lang.t("server.stat.uptime"), |s| s.uptime, duration)),
        )
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn islands_render_on_the_server() {
        for (name, component) in ISLANDS {
            let html = island(name, "en", component).render();
            assert!(
                html.starts_with(&format!(r#"<active-island data-island="{name}""#)),
                "{html}"
            );
        }
        let demo = island("demo", "fr", demo_island).render();
        assert!(
            demo.contains("[[BROCOLIS:v1:"),
            "les jetons sont dans le HTML"
        );
        assert!(demo.contains(r#"<mark class="secret">"#));
    }

    #[test]
    fn faces_are_symmetric_and_stable() {
        let (hue, cells) = identicon("PUB_A");
        assert!(hue < 360);
        for row in 0..5 {
            assert_eq!(cells[row * 5], cells[row * 5 + 4]);
            assert_eq!(cells[row * 5 + 1], cells[row * 5 + 3]);
        }
        assert_eq!(identicon("PUB_A"), identicon("PUB_A"));
        assert_ne!(identicon("PUB_A"), identicon("PUB_B"));
    }

    #[test]
    fn numbers_read_well_in_each_language() {
        assert_eq!(group(Lang::En, 1234567.0), "1,234,567");
        assert_eq!(group(Lang::Fr, 1234.0), "1\u{202f}234");
        assert_eq!(group(Lang::Fr, 12.0), "12");
        assert_eq!(bytes(Lang::Fr, 12_697.0), "12,4 Ko");
        assert_eq!(bytes(Lang::En, 512.0), "512 B");
        assert_eq!(duration(Lang::Fr, 90_061.0), "1 j 01:01:01");
        assert_eq!(duration(Lang::En, 61.0), "00:01:01");
        assert_eq!(short_key("ABCDEFGHIJKLMNOP"), "ABCDEFGHIJKLMN…");
        assert_eq!(short_key("ABC"), "ABC");
    }

    #[test]
    fn numbers_are_found_in_prices() {
        let (before, v, d, sep, after) = parse_number("2,99 €").unwrap();
        assert_eq!(
            (before.as_str(), v, d, sep, after.as_str()),
            ("", 2.99, 2, ',', " €")
        );
        let (before, v, d, _, after) = parse_number("€6.99").unwrap();
        assert_eq!((before.as_str(), v, d, after.as_str()), ("€", 6.99, 2, ""));
        assert_eq!(parse_number("0 €").unwrap().1, 0.0);
        assert!(parse_number("gratuit").is_none());
    }
}
