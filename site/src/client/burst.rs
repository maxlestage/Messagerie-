//! Une gerbe de 🥦, de 🔒 et d'étincelles quand on touche le logo, le bouton
//! principal ou le brocoli du pied de page (`[data-burst]`). Chaque éclat est
//! un petit élément animé par le CSS (`.burst-bit`), retiré ensuite.

use wasm_bindgen::JsCast;
use web_sys::Element;

use super::{document, later, on, random, reduced_motion};

const BITS: [&str; 6] = ["🥦", "🥦", "🔒", "✨", "🔑", "🥦"];

pub fn init() {
    on::<web_sys::MouseEvent>(&document(), "click", |e| {
        let Some(target) = e
            .target()
            .and_then(|t| t.dyn_into::<Element>().ok())
            .and_then(|t| t.closest("[data-burst]").ok().flatten())
        else {
            return;
        };
        if reduced_motion() {
            return;
        }
        let (x, y) = if e.client_x() == 0 && e.client_y() == 0 {
            // Clavier : depuis le centre de l'élément.
            let r = target.get_bounding_client_rect();
            (r.left() + r.width() / 2.0, r.top() + r.height() / 2.0)
        } else {
            (e.client_x() as f64, e.client_y() as f64)
        };
        let _ = target.class_list().remove_1("bursting");
        // Relance l'animation du déclencheur (le logo fait un tour).
        let _ = target.client_width();
        let _ = target.class_list().add_1("bursting");
        burst(x, y);
    });
}

/// Lance une gerbe depuis (x, y), en coordonnées de la fenêtre.
pub fn burst(x: f64, y: f64) {
    let Some(body) = document().body() else {
        return;
    };
    for i in 0..22 {
        let Ok(bit) = document().create_element("span") else {
            continue;
        };
        bit.set_class_name("burst-bit");
        let _ = bit.set_attribute("aria-hidden", "true");
        bit.set_text_content(Some(BITS[i % BITS.len()]));
        let angle = random() * std::f64::consts::TAU;
        let speed = 70.0 + random() * 170.0;
        let _ = bit.set_attribute(
            "style",
            &format!(
                "left:{x:.0}px;top:{y:.0}px;--dx:{:.0}px;--dy:{:.0}px;--r:{:.0}deg;--s:{:.2};--t:{:.0}ms",
                angle.cos() * speed,
                angle.sin() * speed - 60.0,
                (random() - 0.5) * 720.0,
                0.7 + random() * 0.9,
                700.0 + random() * 500.0,
            ),
        );
        let _ = body.append_child(&bit);
        later(1300, move || bit.remove());
    }
}
