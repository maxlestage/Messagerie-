//! La pluie de chiffré derrière le héros : des colonnes de caractères base64
//! tombent doucement ; près du pointeur, ils s'illuminent et laissent voir un
//! 🥦 — le texte se « déchiffre » là où l'on regarde.

use std::cell::Cell;
use std::rc::Rc;

use wasm_bindgen::JsCast;
use web_sys::{CanvasRenderingContext2d, Element, HtmlCanvasElement};

use super::{on_passive, random, reduced_motion, request_frame, root, window};

const GLYPHS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
/// Taille d'un caractère, en pixels CSS.
const CELL: f64 = 18.0;

struct Drop {
    /// Colonne et position de la tête, en cellules.
    col: f64,
    head: f64,
    speed: f64,
    len: usize,
    chars: Vec<u8>,
}

impl Drop {
    fn new(col: f64, rows: f64, scatter: bool) -> Drop {
        let len = 6 + (random() * 14.0) as usize;
        Drop {
            col,
            head: if scatter {
                random() * rows
            } else {
                -(random() * rows * 0.5)
            },
            speed: 4.0 + random() * 9.0,
            len,
            chars: (0..len)
                .map(|_| GLYPHS[(random() * 64.0) as usize % 64])
                .collect(),
        }
    }
}

fn css_var(name: &str) -> String {
    window()
        .get_computed_style(&root())
        .ok()
        .flatten()
        .and_then(|s| s.get_property_value(name).ok())
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "#2f9e4a".to_owned())
}

pub fn start(canvas: Element) {
    let Ok(canvas) = canvas.dyn_into::<HtmlCanvasElement>() else {
        return;
    };
    let Some(ctx) = canvas
        .get_context("2d")
        .ok()
        .flatten()
        .and_then(|c| c.dyn_into::<CanvasRenderingContext2d>().ok())
    else {
        return;
    };
    let pointer = Rc::new(Cell::new((-1e4, -1e4)));
    {
        let pointer = pointer.clone();
        let canvas = canvas.clone();
        on_passive::<web_sys::PointerEvent>(&window(), "pointermove", move |e| {
            let r = canvas.get_bounding_client_rect();
            pointer.set((
                e.client_x() as f64 - r.left(),
                e.client_y() as f64 - r.top(),
            ));
        });
    }
    let calm = reduced_motion();
    let mut drops: Vec<Drop> = Vec::new();
    let mut size = (0.0, 0.0);
    let mut last = 0.0;
    let mut frame = 0u32;
    let (mut brand, mut accent) = (css_var("--brand"), css_var("--accent"));
    request_frame(move |time| {
        // ~30 images par seconde suffisent à une pluie.
        if time - last < 33.0 {
            return true;
        }
        let dt = ((time - last) / 1000.0).min(0.1);
        last = time;
        let rect = canvas.get_bounding_client_rect();
        if rect.bottom() < 0.0 || rect.height() < 1.0 {
            return true; // hors écran : on ne dessine rien
        }
        frame = frame.wrapping_add(1);
        if frame % 60 == 1 {
            // Le thème a pu changer.
            brand = css_var("--brand");
            accent = css_var("--accent");
        }
        let dpr = window().device_pixel_ratio().min(2.0);
        let (w, h) = (rect.width(), rect.height());
        if (w, h) != size {
            size = (w, h);
            canvas.set_width((w * dpr) as u32);
            canvas.set_height((h * dpr) as u32);
            let cols = (w / CELL).ceil() as usize;
            let rows = h / CELL;
            // Une colonne sur deux porte une goutte : la pluie reste légère.
            drops = (0..cols)
                .filter(|_| random() < 0.55)
                .map(|c| Drop::new(c as f64, rows, true))
                .collect();
        }
        let rows = h / CELL;
        let _ = ctx.set_transform(dpr, 0.0, 0.0, dpr, 0.0, 0.0);
        ctx.clear_rect(0.0, 0.0, w, h);
        ctx.set_font(&format!(
            "600 {}px ui-monospace, Menlo, monospace",
            CELL * 0.8
        ));
        ctx.set_text_align("center");
        ctx.set_text_baseline("middle");
        let (px, py) = pointer.get();
        for drop in &mut drops {
            if !calm {
                drop.head += drop.speed * dt;
                // De temps en temps, un caractère change.
                if random() < 0.08 {
                    let k = (random() * drop.len as f64) as usize % drop.len;
                    drop.chars[k] = GLYPHS[(random() * 64.0) as usize % 64];
                }
            }
            let x = drop.col * CELL + CELL / 2.0;
            for k in 0..drop.len {
                let row = drop.head.floor() - k as f64;
                if row < 0.0 || row > rows {
                    continue;
                }
                let y = row * CELL + CELL / 2.0;
                let near = ((x - px).powi(2) + (y - py).powi(2)).sqrt();
                let fade = 1.0 - k as f64 / drop.len as f64;
                if near < 110.0 {
                    // Sous le pointeur : le chiffré s'illumine et se déchiffre.
                    let glow = 1.0 - near / 110.0;
                    ctx.set_global_alpha((0.25 + glow * 0.75) * fade.max(0.3));
                    ctx.set_fill_style_str(&accent);
                    let c = if glow > 0.75 && k % 5 == 0 {
                        "🥦".to_string()
                    } else {
                        (drop.chars[k] as char).to_string()
                    };
                    let _ = ctx.fill_text(&c, x, y);
                } else {
                    ctx.set_global_alpha(if k == 0 { 0.5 } else { 0.22 * fade });
                    ctx.set_fill_style_str(if k == 0 { &accent } else { &brand });
                    let _ = ctx.fill_text(&(drop.chars[k] as char).to_string(), x, y);
                }
            }
            if drop.head - drop.len as f64 > rows {
                *drop = Drop::new(drop.col, rows, false);
            }
        }
        ctx.set_global_alpha(1.0);
        !calm
    });
}
