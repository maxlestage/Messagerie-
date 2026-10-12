//! « Film de grains » : des milliers de particules (WebGL2) qui se recomposent
//! d'une forme à l'autre au fil du défilement, une phrase par étape.
//!
//! Les formes ne sont pas dessinées à la main : chaque étape est rendue dans un
//! canvas 2D hors écran (emoji, texte, contour), puis on y prélève des points
//! colorés. Les particules volent d'un nuage à l'autre ; le pointeur les écarte.

use std::cell::RefCell;
use std::rc::Rc;

use js_sys::Float32Array;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{
    CanvasRenderingContext2d, Element, HtmlCanvasElement, HtmlElement,
    WebGl2RenderingContext as Gl, WebGlProgram, WebGlShader,
};

use super::{document, on_passive, reduced_motion, request_frame, root, window};

/// Une étape du film : comment dessiner la forme. Les phrases qui
/// l'accompagnent sont dans le HTML (`[data-station]`), rendu par le serveur.
struct Station {
    draw: fn(&CanvasRenderingContext2d, f64),
}

const STATIONS: [Station; 6] = [
    Station {
        draw: draw_broccoli,
    },
    Station { draw: draw_bubble },
    Station { draw: draw_cipher },
    Station { draw: draw_keys },
    Station { draw: draw_watch },
    Station { draw: draw_finale },
];

/// Côté du canvas hors écran où l'on dessine chaque forme.
const SAMPLE: f64 = 360.0;
const EMOJI_FONT: &str =
    "'Apple Color Emoji','Segoe UI Emoji','Noto Color Emoji','Twemoji Mozilla',sans-serif";

// ---------- Les formes ----------

fn emoji(ctx: &CanvasRenderingContext2d, glyph: &str, size: f64, y: f64) {
    ctx.set_font(&format!("{size}px {EMOJI_FONT}"));
    ctx.set_text_align("center");
    ctx.set_text_baseline("middle");
    let _ = ctx.fill_text(glyph, SAMPLE / 2.0, y);
}

fn draw_broccoli(ctx: &CanvasRenderingContext2d, _: f64) {
    emoji(ctx, "🥦", 270.0, SAMPLE / 2.0 + 10.0);
}

fn draw_bubble(ctx: &CanvasRenderingContext2d, _: f64) {
    let (x, y, w, h, r) = (30.0, 95.0, 300.0, 150.0, 38.0);
    ctx.begin_path();
    ctx.move_to(x + r, y);
    let _ = ctx.arc_to(x + w, y, x + w, y + h, r);
    let _ = ctx.arc_to(x + w, y + h, x, y + h, r);
    ctx.line_to(x + 90.0, y + h);
    ctx.line_to(x + 40.0, y + h + 45.0);
    ctx.line_to(x + 55.0, y + h);
    let _ = ctx.arc_to(x, y + h, x, y, r);
    let _ = ctx.arc_to(x, y, x + w, y, r);
    ctx.close_path();
    ctx.set_line_width(12.0);
    ctx.set_stroke_style_str("#6fd98a");
    ctx.stroke();
    ctx.set_fill_style_str("#f4fbf5");
    ctx.set_font("bold 44px system-ui, -apple-system, sans-serif");
    ctx.set_text_align("center");
    ctx.set_text_baseline("middle");
    let _ = ctx.fill_text_with_max_width("20h ce soir ?", x + w / 2.0, y + h / 2.0, w - 56.0);
}

fn draw_cipher(ctx: &CanvasRenderingContext2d, seed: f64) {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    ctx.set_font("bold 30px ui-monospace, Menlo, monospace");
    ctx.set_text_align("left");
    ctx.set_text_baseline("middle");
    let mut state = (seed * 1e9) as u64 | 1;
    for line in 0..8 {
        let text: String = (0..15)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                ALPHABET[(state % ALPHABET.len() as u64) as usize] as char
            })
            .collect();
        let color = if line % 3 == 1 { "#b6f07a" } else { "#4cc66a" };
        ctx.set_fill_style_str(color);
        let _ = ctx.fill_text(&text, 22.0, 52.0 + line as f64 * 36.0);
    }
}

fn draw_keys(ctx: &CanvasRenderingContext2d, _: f64) {
    emoji(ctx, "📱", 120.0, SAMPLE / 2.0 + 30.0);
    ctx.save();
    let _ = ctx.translate(-115.0, 0.0);
    emoji(ctx, "📱", 120.0, SAMPLE / 2.0 + 30.0);
    let _ = ctx.translate(230.0, 0.0);
    emoji(ctx, "📱", 120.0, SAMPLE / 2.0 + 30.0);
    ctx.restore();
    emoji(ctx, "🔑", 90.0, 70.0);
}

fn draw_watch(ctx: &CanvasRenderingContext2d, _: f64) {
    emoji(ctx, "⌚", 260.0, SAMPLE / 2.0 + 8.0);
}

fn draw_finale(ctx: &CanvasRenderingContext2d, _: f64) {
    emoji(ctx, "🥦", 190.0, 140.0);
    ctx.set_fill_style_str("#f4fbf5");
    ctx.set_font("800 70px system-ui, -apple-system, sans-serif");
    ctx.set_text_align("center");
    ctx.set_text_baseline("middle");
    let _ = ctx.fill_text("Brocolis", SAMPLE / 2.0, 300.0);
}

// ---------- Échantillonnage ----------

/// Une forme prête : N positions (x, y dans [-1, 1]) et N couleurs (r, g, b).
struct Shape {
    pos: Vec<f32>,
    col: Vec<f32>,
}

fn random() -> f32 {
    js_sys::Math::random() as f32
}

fn sample_shape(station: &Station, n: usize) -> Option<Shape> {
    let canvas: HtmlCanvasElement = document().create_element("canvas").ok()?.dyn_into().ok()?;
    canvas.set_width(SAMPLE as u32);
    canvas.set_height(SAMPLE as u32);
    let ctx: CanvasRenderingContext2d = canvas.get_context("2d").ok()??.dyn_into().ok()?;
    (station.draw)(&ctx, js_sys::Math::random());
    let data = ctx.get_image_data(0.0, 0.0, SAMPLE, SAMPLE).ok()?.data();

    // Points opaques, un pixel sur deux.
    let side = SAMPLE as usize;
    let mut points: Vec<(f32, f32, [f32; 3])> = Vec::new();
    for y in (0..side).step_by(2) {
        for x in (0..side).step_by(2) {
            let i = (y * side + x) * 4;
            if data[i + 3] > 140 {
                // Couleurs relevées : sur fond sombre, en mélange additif.
                let lift = |c: u8| (c as f32 / 255.0 * 0.8 + 0.2).min(1.0);
                let col = [lift(data[i]), lift(data[i + 1]), lift(data[i + 2])];
                let px = x as f32 / SAMPLE as f32 * 2.0 - 1.0;
                let py = 1.0 - y as f32 / SAMPLE as f32 * 2.0;
                points.push((px, py, col));
            }
        }
    }
    if points.len() < 50 {
        return None; // police d'emoji absente : on laisse tomber cette forme
    }

    let mut pos = Vec::with_capacity(n * 2);
    let mut col = Vec::with_capacity(n * 3);
    for k in 0..n {
        // Tirage sans remise tant qu'il reste des points, puis réutilisation
        // avec un léger flou.
        let idx = if k < points.len() {
            let len = points.len();
            let j = (k + (random() * (len - k) as f32) as usize).min(len - 1);
            points.swap(k, j);
            k
        } else {
            (random() * points.len() as f32) as usize % points.len()
        };
        let (x, y, c) = points[idx];
        let jitter = 0.006;
        pos.push(x + (random() - 0.5) * jitter);
        pos.push(y + (random() - 0.5) * jitter);
        col.extend_from_slice(&c);
    }
    Some(Shape { pos, col })
}

// ---------- WebGL ----------

const VERTEX: &str = r#"#version 300 es
in vec2 a_pos;
in vec3 a_col;
in float a_size;
uniform vec2 u_scale;
uniform vec2 u_offset;
uniform float u_point;
out vec3 v_col;
void main() {
    gl_Position = vec4(a_pos * u_scale + u_offset, 0.0, 1.0);
    gl_PointSize = u_point * a_size;
    v_col = a_col;
}"#;

const FRAGMENT: &str = r#"#version 300 es
precision mediump float;
in vec3 v_col;
out vec4 color;
void main() {
    vec2 d = gl_PointCoord - 0.5;
    float a = smoothstep(0.5, 0.0, length(d));
    color = vec4(v_col * a, a * 0.85);
}"#;

fn compile(gl: &Gl, kind: u32, src: &str) -> Option<WebGlShader> {
    let shader = gl.create_shader(kind)?;
    gl.shader_source(&shader, src);
    gl.compile_shader(&shader);
    if gl
        .get_shader_parameter(&shader, Gl::COMPILE_STATUS)
        .as_bool()
        == Some(true)
    {
        Some(shader)
    } else {
        web_sys::console::warn_1(&gl.get_shader_info_log(&shader).unwrap_or_default().into());
        None
    }
}

fn program(gl: &Gl) -> Option<WebGlProgram> {
    let vs = compile(gl, Gl::VERTEX_SHADER, VERTEX)?;
    let fs = compile(gl, Gl::FRAGMENT_SHADER, FRAGMENT)?;
    let prog = gl.create_program()?;
    gl.attach_shader(&prog, &vs);
    gl.attach_shader(&prog, &fs);
    gl.link_program(&prog);
    (gl.get_program_parameter(&prog, Gl::LINK_STATUS).as_bool() == Some(true)).then_some(prog)
}

/// Lissage « ease in-out » d'un paramètre dans [0, 1].
fn smooth(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

/// Tout l'état du film, partagé avec la boucle d'animation.
struct Engine {
    gl: Gl,
    canvas: HtmlCanvasElement,
    section: HtmlElement,
    n: usize,
    shapes: Vec<Shape>,
    /// Par particule : direction d'envol, retard, phase, taille.
    dir: Vec<f32>,
    delay: Vec<f32>,
    phase: Vec<f32>,
    pos: Vec<f32>,
    col: Vec<f32>,
    pos_view: Float32Array,
    col_view: Float32Array,
    pos_buf: web_sys::WebGlBuffer,
    col_buf: web_sys::WebGlBuffer,
    u_scale: Option<web_sys::WebGlUniformLocation>,
    u_offset: Option<web_sys::WebGlUniformLocation>,
    u_point: Option<web_sys::WebGlUniformLocation>,
    calm: bool,
    pointer: (f32, f32),
    captions: Vec<web_sys::Element>,
    counter: Option<web_sys::Element>,
    shown: Option<usize>,
    /// La barre de navigation survole le film : elle passe en sombre.
    under_nav: bool,
}

impl Engine {
    fn new(canvas: HtmlCanvasElement, section: HtmlElement, calm: bool) -> Option<Self> {
        let opts = js_sys::Object::new();
        for (k, v) in [
            ("antialias", false),
            ("alpha", true),
            ("premultipliedAlpha", true),
        ] {
            let _ = js_sys::Reflect::set(&opts, &k.into(), &JsValue::from_bool(v));
        }
        let gl: Gl = canvas
            .get_context_with_context_options("webgl2", &opts)
            .ok()??
            .dyn_into()
            .ok()?;
        let prog = program(&gl)?;
        gl.use_program(Some(&prog));

        // Moins de grains sur petit écran : fluide sur téléphone.
        let w = window().inner_width().ok()?.as_f64()?;
        let n = if w < 600.0 {
            4200
        } else if w < 1100.0 {
            6500
        } else {
            9000
        };

        let shapes: Vec<Shape> = STATIONS.iter().filter_map(|s| sample_shape(s, n)).collect();
        if shapes.len() != STATIONS.len() {
            return None;
        }

        let mut dir = Vec::with_capacity(n * 2);
        let mut size = Vec::with_capacity(n);
        let (mut delay, mut phase) = (Vec::with_capacity(n), Vec::with_capacity(n));
        for _ in 0..n {
            let a = random() * std::f32::consts::TAU;
            let r = 0.35 + random() * 0.9;
            dir.push(a.cos() * r);
            dir.push(a.sin() * r);
            delay.push(random());
            phase.push(random() * std::f32::consts::TAU);
            size.push(0.6 + random() * 0.9);
        }

        let attrib = |name: &str, comps: i32, data: &[f32]| -> Option<web_sys::WebGlBuffer> {
            let buf = gl.create_buffer()?;
            gl.bind_buffer(Gl::ARRAY_BUFFER, Some(&buf));
            let view = Float32Array::from(data);
            gl.buffer_data_with_array_buffer_view(Gl::ARRAY_BUFFER, &view, Gl::DYNAMIC_DRAW);
            let loc = gl.get_attrib_location(&prog, name);
            if loc >= 0 {
                gl.enable_vertex_attrib_array(loc as u32);
                gl.vertex_attrib_pointer_with_i32(loc as u32, comps, Gl::FLOAT, false, 0, 0);
            }
            Some(buf)
        };
        let pos = shapes[0].pos.clone();
        let col = shapes[0].col.clone();
        let pos_buf = attrib("a_pos", 2, &pos)?;
        let col_buf = attrib("a_col", 3, &col)?;
        attrib("a_size", 1, &size)?;

        gl.enable(Gl::BLEND);
        gl.blend_func(Gl::ONE, Gl::ONE); // additif : les grains denses s'illuminent
        gl.clear_color(0.0, 0.0, 0.0, 0.0);

        let captions = (0..STATIONS.len())
            .filter_map(|i| {
                section
                    .query_selector(&format!("[data-station='{i}']"))
                    .ok()?
            })
            .collect();
        let counter = section.query_selector(".film-count b").ok().flatten();

        Some(Engine {
            u_scale: gl.get_uniform_location(&prog, "u_scale"),
            u_offset: gl.get_uniform_location(&prog, "u_offset"),
            u_point: gl.get_uniform_location(&prog, "u_point"),
            pos_view: Float32Array::new_with_length((n * 2) as u32),
            col_view: Float32Array::new_with_length((n * 3) as u32),
            gl,
            canvas,
            section,
            n,
            shapes,
            dir,
            delay,
            phase,
            pos,
            col,
            pos_buf,
            col_buf,
            calm,
            pointer: (9.0, 9.0),
            captions,
            counter,
            shown: None,
            under_nav: false,
        })
    }

    /// Avancement du film dans [0, étapes - 1], d'après la position de la
    /// section épinglée dans la fenêtre. `None` si elle est hors écran.
    fn progress(&self) -> Option<f32> {
        let rect = self.section.get_bounding_client_rect();
        let vh = window().inner_height().ok()?.as_f64()?;
        if rect.bottom() < 0.0 || rect.top() > vh {
            return None;
        }
        let travel = (rect.height() - vh).max(1.0);
        let p = (-rect.top() / travel).clamp(0.0, 1.0) as f32;
        Some(p * (STATIONS.len() - 1) as f32)
    }

    fn resize(&self) -> (f32, f32) {
        let dpr = window().device_pixel_ratio().min(2.0);
        let w = self.canvas.client_width().max(1) as f64;
        let h = self.canvas.client_height().max(1) as f64;
        let (pw, ph) = ((w * dpr) as u32, (h * dpr) as u32);
        if self.canvas.width() != pw || self.canvas.height() != ph {
            self.canvas.set_width(pw);
            self.canvas.set_height(ph);
        }
        self.gl.viewport(0, 0, pw as i32, ph as i32);
        // Forme carrée, logée dans le plus petit côté, au-dessus des légendes.
        let side = w.min(h * 0.78) * 0.86;
        let sx = (side / w) as f32;
        let sy = (side / h) as f32;
        self.gl.uniform2f(self.u_scale.as_ref(), sx, sy);
        self.gl.uniform2f(self.u_offset.as_ref(), 0.0, 0.12);
        let base = if w < 600.0 { 2.2 } else { 2.6 };
        self.gl
            .uniform1f(self.u_point.as_ref(), (base * dpr) as f32);
        (sx, sy)
    }

    /// Bascule `html.over-film` quand le film passe sous la barre de navigation.
    fn track_nav(&mut self) {
        let rect = self.section.get_bounding_client_rect();
        let under = rect.top() <= 40.0 && rect.bottom() >= 40.0;
        if under != self.under_nav {
            let _ = root().class_list().toggle_with_force("over-film", under);
            self.under_nav = under;
        }
    }

    fn frame(&mut self, time: f64) {
        self.track_nav();
        let Some(s) = self.progress() else { return };
        let (sx, sy) = self.resize();

        // Étape courante et transition vers la suivante : on tient la forme
        // un moment, puis les grains s'envolent et se reposent.
        let last = STATIONS.len() - 1;
        let i = (s.floor() as usize).min(last);
        let j = (i + 1).min(last);
        let f = s - i as f32;
        let t = smooth((f - 0.22) / 0.56);

        let caption = (s.round() as usize).min(last);
        if self.shown != Some(caption) {
            for (k, el) in self.captions.iter().enumerate() {
                let _ = el.class_list().toggle_with_force("on", k == caption);
            }
            let _ = self
                .section
                .class_list()
                .toggle_with_force("at-end", caption == last);
            if let Some(c) = &self.counter {
                c.set_text_content(Some(&format!("{:02}", caption + 1)));
            }
            self.shown = Some(caption);
        }

        // Fil de progression du film (`--film-p`, de 0 à 1).
        let _ = self
            .section
            .style()
            .set_property("--film-p", &format!("{:.4}", s / last as f32));

        let time = (time / 1000.0) as f32;
        let (a, b) = (&self.shapes[i], &self.shapes[j]);
        // Pointeur, ramené dans l'espace des formes.
        let (px, py) = (self.pointer.0 / sx, (self.pointer.1 - 0.12) / sy);
        for k in 0..self.n {
            let tk = if self.calm {
                t
            } else {
                smooth(t * 1.6 - self.delay[k] * 0.6)
            };
            let lift = if self.calm {
                0.0
            } else {
                (tk * std::f32::consts::PI).sin()
            };
            let (ax, ay) = (a.pos[2 * k], a.pos[2 * k + 1]);
            let (bx, by) = (b.pos[2 * k], b.pos[2 * k + 1]);
            let mut x = ax + (bx - ax) * tk + self.dir[2 * k] * lift * 0.55;
            let mut y = ay + (by - ay) * tk + self.dir[2 * k + 1] * lift * 0.55;
            if !self.calm {
                let ph = self.phase[k];
                x += (time * 0.9 + ph).sin() * 0.004;
                y += (time * 1.1 + ph * 1.3).cos() * 0.004;
                // Le pointeur écarte les grains.
                let (dx, dy) = (x - px, y - py);
                let d2 = dx * dx + dy * dy;
                if d2 < 0.04 {
                    let d = d2.sqrt().max(0.001);
                    let push = (0.2 - d) * 0.6;
                    x += dx / d * push;
                    y += dy / d * push;
                }
            }
            self.pos[2 * k] = x;
            self.pos[2 * k + 1] = y;
            for c in 0..3 {
                let (ca, cb) = (a.col[3 * k + c], b.col[3 * k + c]);
                self.col[3 * k + c] = ca + (cb - ca) * tk;
            }
        }

        let gl = &self.gl;
        self.pos_view.copy_from(&self.pos);
        self.col_view.copy_from(&self.col);
        gl.bind_buffer(Gl::ARRAY_BUFFER, Some(&self.pos_buf));
        gl.buffer_sub_data_with_i32_and_array_buffer_view(Gl::ARRAY_BUFFER, 0, &self.pos_view);
        gl.bind_buffer(Gl::ARRAY_BUFFER, Some(&self.col_buf));
        gl.buffer_sub_data_with_i32_and_array_buffer_view(Gl::ARRAY_BUFFER, 0, &self.col_view);
        gl.clear(Gl::COLOR_BUFFER_BIT);
        gl.draw_arrays(Gl::POINTS, 0, self.n as i32);
    }
}

/// Démarre le film dans `section` (la section `#film` rendue par le serveur).
/// Sans WebGL ou sans police d'emoji, les phrases s'affichent simplement.
pub fn start(section: Element) {
    let Some(canvas) = section
        .query_selector(".film-canvas")
        .ok()
        .flatten()
        .and_then(|c| c.dyn_into::<HtmlCanvasElement>().ok())
    else {
        return;
    };
    let Ok(section_el) = section.clone().dyn_into::<HtmlElement>() else {
        return;
    };
    let Some(engine) = Engine::new(canvas, section_el, reduced_motion()) else {
        let _ = section.class_list().add_1("no-gl");
        return;
    };
    let engine = Rc::new(RefCell::new(engine));
    // Pointeur, en coordonnées de découpe (-1..1).
    {
        let engine = engine.clone();
        on_passive::<web_sys::PointerEvent>(&window(), "pointermove", move |e| {
            let Ok(mut eng) = engine.try_borrow_mut() else {
                return;
            };
            let rect = eng.canvas.get_bounding_client_rect();
            let x = ((e.client_x() as f64 - rect.left()) / rect.width()) * 2.0 - 1.0;
            let y = 1.0 - ((e.client_y() as f64 - rect.top()) / rect.height()) * 2.0;
            eng.pointer = (x as f32, y as f32);
        });
    }
    request_frame(move |time| {
        engine.borrow_mut().frame(time);
        true
    });
}
