//! Best-effort system clipboard access via the platform's own tools
//! (`clip` on Windows, `pbcopy` on macOS, `termux-clipboard-set` on Android/Termux,
//! `wl-copy` / `xclip` / `xsel` on Linux and BSD).

use std::io::Write;
use std::process::{Command, Stdio};

use crate::error::{Error, Result};

type Tool = (&'static str, &'static [&'static str]);

#[cfg(windows)]
fn tools() -> Vec<Tool> {
    vec![("clip", &[])]
}

#[cfg(target_os = "macos")]
fn tools() -> Vec<Tool> {
    vec![("pbcopy", &[])]
}

#[cfg(target_os = "android")]
fn tools() -> Vec<Tool> {
    // Provided by `pkg install termux-api` together with the Termux:API app.
    vec![("termux-clipboard-set", &[])]
}

#[cfg(not(any(windows, target_os = "macos", target_os = "android")))]
fn tools() -> Vec<Tool> {
    let mut list: Vec<Tool> = Vec::new();
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        list.push(("wl-copy", &[]));
    }
    list.push(("xclip", &["-selection", "clipboard"]));
    list.push(("xsel", &["--clipboard", "--input"]));
    list.push(("wl-copy", &[]));
    list
}

fn run_tool(tool: &Tool, text: &str) -> std::io::Result<bool> {
    let mut child = Command::new(tool.0)
        .args(tool.1)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(text.as_bytes())?;
    }
    Ok(child.wait()?.success())
}

fn copy_with(tools: &[Tool], text: &str) -> Result<()> {
    let mut last_failure = None;
    for tool in tools {
        match run_tool(tool, text) {
            Ok(true) => return Ok(()),
            Ok(false) => last_failure = Some(format!("`{}` failed", tool.0)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => last_failure = Some(format!("`{}`: {e}", tool.0)),
        }
    }
    Err(Error::Clipboard(last_failure.unwrap_or_else(|| {
        "no clipboard tool found (install xclip, xsel or wl-clipboard; on Termux: pkg install termux-api and install the Termux:API app)".into()
    })))
}

/// Copies `text` to the system clipboard.
pub fn copy(text: &str) -> Result<()> {
    copy_with(&tools(), text)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("otpforge-clip-{}-{name}", std::process::id()))
    }

    #[test]
    fn writes_text_to_first_working_tool() {
        let out = tmp("ok");
        let script = format!("cat > '{}'", out.display());
        let script: &'static str = Box::leak(script.into_boxed_str());
        let args: &'static [&'static str] = Box::leak(Box::new(["-c", script]));
        let tools: Vec<Tool> = vec![("definitely-not-installed-xyz", &[]), ("sh", args)];
        copy_with(&tools, "123456").unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "123456");
        let _ = std::fs::remove_file(out);
    }

    #[test]
    fn reports_missing_and_failing_tools() {
        let missing: Vec<Tool> = vec![("definitely-not-installed-xyz", &[])];
        assert!(
            matches!(copy_with(&missing, "1"), Err(Error::Clipboard(m)) if m.contains("no clipboard tool"))
        );
        let failing: Vec<Tool> = vec![("sh", &["-c", "exit 3"])];
        assert!(
            matches!(copy_with(&failing, "1"), Err(Error::Clipboard(m)) if m.contains("failed"))
        );
    }
}
