/*******************************************************************
 * Filename:        halfblock.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     Convert a decoded image to terminal halfblock lines
 * Notes:           ▄ char: fg = lower half pixel, bg = upper half pixel.
 *                  Two image pixel rows → one terminal row.
 *                  Transparent pixels (alpha < 128) use Color::Reset.
 *******************************************************************/

use image::{DynamicImage, imageops::FilterType};
use ratatui::{
    style::{Color, Style},
    text::{Line, Span},
};

// Decode raw bytes into a DynamicImage; returns human-readable error string
pub fn decode(bytes: &[u8]) -> Result<DynamicImage, String> {
    image::load_from_memory(bytes).map_err(|e| e.to_string())
}

// Render an image into halfblock terminal lines at the given dimensions
pub fn to_lines(img: &DynamicImage, term_width: u16, term_height: u16) -> Vec<Line<'static>> {
    let pw = term_width.max(1) as u32;
    let ph = (term_height.max(1) as u32) * 2; // 2 pixel rows per terminal row

    let resized = img.resize_exact(pw, ph, FilterType::Triangle);
    let rgba = resized.to_rgba8();
    let (w, h) = rgba.dimensions();

    let mut lines = Vec::new();
    let mut py = 0u32;

    while py < h {
        let mut spans = Vec::new();

        for px in 0..w {
            let top = rgba[(px, py)];
            let bot = if py + 1 < h { rgba[(px, py + 1)] } else { top };

            let top_opaque = top[3] >= 128;
            let bot_opaque = bot[3] >= 128;

            let (ch, fg, bg) = match (top_opaque, bot_opaque) {
                (true, true) => (
                    "\u{2584}", // ▄ lower half block
                    Color::Rgb(bot[0], bot[1], bot[2]),
                    Color::Rgb(top[0], top[1], top[2]),
                ),
                (true, false) => (
                    "\u{2580}", // ▀ upper half block
                    Color::Rgb(top[0], top[1], top[2]),
                    Color::Reset,
                ),
                (false, true) => (
                    "\u{2584}", // ▄ lower half block
                    Color::Rgb(bot[0], bot[1], bot[2]),
                    Color::Reset,
                ),
                (false, false) => (" ", Color::Reset, Color::Reset),
            };

            spans.push(Span::styled(
                ch.to_string(),
                Style::default().fg(fg).bg(bg),
            ));
        }

        lines.push(Line::from(spans));
        py += 2;
    }

    lines
}
