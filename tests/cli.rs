use std::io::Write;
use std::process::{Command, Output, Stdio};

const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_otpforge"));
    cmd.env_remove("OTPFORGE_SECRET");
    cmd
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn code_matches_rfc6238_vector() {
    let out = bin()
        .args([
            "code", "--secret", RFC_SECRET, "--digits", "8", "--time", "59",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(stdout(&out).trim(), "94287082");
}

#[test]
fn secret_from_stdin_and_env() {
    let mut child = bin()
        .args(["code", "--secret-stdin", "--digits", "8", "--time", "59"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{RFC_SECRET}\n").as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(stdout(&out).trim(), "94287082");

    let out = bin()
        .env("OTPFORGE_SECRET", RFC_SECRET)
        .args(["code", "--digits", "8", "--time", "59"])
        .output()
        .unwrap();
    assert_eq!(stdout(&out).trim(), "94287082");
}

#[test]
fn verify_exit_codes() {
    let ok = bin()
        .args([
            "verify", "--secret", RFC_SECRET, "--digits", "8", "--time", "59", "--code", "94287082",
        ])
        .output()
        .unwrap();
    assert_eq!(ok.status.code(), Some(0));

    let bad = bin()
        .args([
            "verify", "--secret", RFC_SECRET, "--digits", "8", "--time", "59", "--code", "00000000",
        ])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1));

    let malformed = bin()
        .args(["verify", "--secret", RFC_SECRET, "--code", "abc"])
        .output()
        .unwrap();
    assert_eq!(malformed.status.code(), Some(2));
}

#[test]
fn generate_json_is_consistent() {
    let out = bin()
        .args([
            "generate",
            "alice@example.com",
            "--issuer",
            "ACME Co",
            "--format",
            "json",
            "--backup-codes",
            "3",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let secret = v["secret"].as_str().unwrap();
    assert_eq!(secret.len(), 32);
    assert!(v["uri"]
        .as_str()
        .unwrap()
        .starts_with("otpauth://totp/ACME%20Co:alice%40example.com?secret="));
    assert_eq!(v["backup_codes"].as_array().unwrap().len(), 3);

    let code = v["current_code"].as_str().unwrap();
    let verified = bin()
        .env("OTPFORGE_SECRET", secret)
        .args(["verify", "--code", code, "--window", "1"])
        .output()
        .unwrap();
    assert_eq!(verified.status.code(), Some(0));
}

#[test]
fn generate_text_with_qr() {
    let out = bin()
        .args(["generate", "bob", "--qr", "--backup-codes", "0"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("Secret:"));
    assert!(!text.contains("Backup codes"));
    assert!(text.lines().count() > 15);
}

#[test]
fn svg_output_refuses_overwrite_without_force() {
    let path = std::env::temp_dir().join(format!("otpforge-test-{}.svg", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let run = |force: bool| {
        let mut cmd = bin();
        cmd.args(["generate", "carol", "--qr-svg"]).arg(&path);
        if force {
            cmd.arg("--force");
        }
        cmd.output().unwrap()
    };
    assert!(run(false).status.success());
    assert!(std::fs::read_to_string(&path).unwrap().contains("<svg"));
    assert_eq!(run(false).status.code(), Some(2));
    assert!(run(true).status.success());
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn rejects_invalid_input() {
    let qr_json = bin()
        .args(["generate", "x", "--qr", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(qr_json.status.code(), Some(2));

    let bad_secret = bin().args(["code", "--secret", "!!!"]).output().unwrap();
    assert_eq!(bad_secret.status.code(), Some(2));

    let missing = bin().args(["code"]).output().unwrap();
    assert_eq!(missing.status.code(), Some(2));
}

#[test]
fn completions_are_emitted() {
    let out = bin().args(["completions", "bash"]).output().unwrap();
    assert!(out.status.success());
    assert!(stdout(&out).contains("otpforge"));
}
