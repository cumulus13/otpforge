//! QR code rendering for provisioning URIs.

use qrcode::render::{svg, unicode};
use qrcode::{EcLevel, QrCode};

use crate::error::{Error, Result};

fn encode(data: &str) -> Result<QrCode> {
    QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M)
        .map_err(|e| Error::Qr(e.to_string()))
}

/// Renders a compact Unicode QR code for terminals.
///
/// `light_background` selects the colour mapping for terminals with a light
/// background; the default expects a dark one.
pub fn render_terminal(data: &str, light_background: bool) -> Result<String> {
    let code = encode(data)?;
    let (dark, light) = if light_background {
        (unicode::Dense1x2::Dark, unicode::Dense1x2::Light)
    } else {
        (unicode::Dense1x2::Light, unicode::Dense1x2::Dark)
    };
    Ok(code
        .render::<unicode::Dense1x2>()
        .dark_color(dark)
        .light_color(light)
        .quiet_zone(true)
        .build())
}

/// Renders the QR code as a standalone SVG document.
pub fn render_svg(data: &str) -> Result<String> {
    let code = encode(data)?;
    Ok(code
        .render::<svg::Color>()
        .min_dimensions(320, 320)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .quiet_zone(true)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    const URI: &str =
        "otpauth://totp/ACME:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME";

    #[test]
    fn terminal_output_is_nonempty_multiline() {
        let out = render_terminal(URI, false).unwrap();
        assert!(out.lines().count() > 10);
        assert_ne!(out, render_terminal(URI, true).unwrap());
    }

    #[test]
    fn svg_output_is_valid_document() {
        let out = render_svg(URI).unwrap();
        assert!(out.contains("<svg"));
        assert!(out.trim_end().ends_with("</svg>"));
    }
}
