use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PYPI_URI: &str =
    "otpauth://totp/PyPI:hadi?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=PyPI&digits=8";

struct Env {
    dir: PathBuf,
    vault: PathBuf,
}

impl Env {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("otpforge-it-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let vault = dir.join("vault.json");
        Self { dir, vault }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_otpforge"));
        c.env_remove("OTPFORGE_SECRET")
            .env_remove("OTPFORGE_PASSPHRASE")
            .env("OTPFORGE_VAULT", &self.vault)
            .stdin(Stdio::null());
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd().args(args).output().unwrap()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn add_from_uri_then_get_code() {
    let env = Env::new("uri");
    let added = env.run(&["add", "pypi", PYPI_URI]);
    assert!(added.status.success());
    assert!(out(&added).contains("Added 'pypi'"));

    // URI parameters (digits=8) are honoured
    let code = env.run(&["code", "pypi", "--time", "59"]);
    assert_eq!(out(&code).trim(), "94287082");

    // `otpforge NAME` shorthand and unique-prefix matching
    let short = env.run(&["pyp"]);
    assert!(short.status.success());
    assert_eq!(out(&short).trim().len(), 8);

    let list = env.run(&["list"]);
    let text = out(&list);
    assert!(text.contains("pypi") && text.contains("PyPI") && text.contains("hadi"));
    assert!(!text.contains(RFC_SECRET));
}

#[test]
fn add_from_stdin_and_base32() {
    let env = Env::new("stdin");
    let mut child = env
        .cmd()
        .args(["add", "bank", "--digits", "8"])
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
    assert!(child.wait_with_output().unwrap().status.success());
    assert_eq!(
        out(&env.run(&["code", "bank", "--time", "59"])).trim(),
        "94287082"
    );
}

#[test]
fn duplicates_reserved_names_and_missing() {
    let env = Env::new("dup");
    assert!(env.run(&["add", "pypi", RFC_SECRET]).status.success());
    assert_eq!(env.run(&["add", "pypi", RFC_SECRET]).status.code(), Some(2));
    assert!(env
        .run(&["add", "pypi", RFC_SECRET, "--force"])
        .status
        .success());
    assert_eq!(env.run(&["add", "list", RFC_SECRET]).status.code(), Some(2));
    assert_eq!(
        env.run(&["add", "bad name", RFC_SECRET]).status.code(),
        Some(2)
    );
    assert_eq!(env.run(&["nothing"]).status.code(), Some(2));
    assert_eq!(env.run(&["code", "nothing"]).status.code(), Some(2));
}

#[test]
fn verify_saved_account_and_remove() {
    let env = Env::new("verify");
    env.run(&["add", "pypi", PYPI_URI]);
    let ok = env.run(&["verify", "pypi", "--code", "94287082", "--time", "59"]);
    assert_eq!(ok.status.code(), Some(0));
    let bad = env.run(&["verify", "pypi", "--code", "00000000", "--time", "59"]);
    assert_eq!(bad.status.code(), Some(1));

    assert_eq!(env.run(&["remove", "pypi"]).status.code(), Some(2)); // needs --yes without a TTY
    assert!(env.run(&["remove", "pypi", "--yes"]).status.success());
    assert_eq!(env.run(&["pypi"]).status.code(), Some(2));
}

#[test]
fn export_roundtrips_through_add() {
    let env = Env::new("export");
    env.run(&["add", "pypi", PYPI_URI]);
    let uri = out(&env.run(&["export", "pypi"])).trim().to_owned();
    assert!(uri.starts_with("otpauth://totp/PyPI:hadi?secret="));
    assert!(env.run(&["add", "copy", &uri]).status.success());
    let a = env.run(&["code", "pypi", "--time", "1234567890"]);
    let b = env.run(&["code", "copy", "--time", "1234567890"]);
    assert_eq!(out(&a), out(&b));
}

#[test]
fn encrypted_vault_lifecycle() {
    let env = Env::new("enc");
    env.run(&["add", "pypi", PYPI_URI]);
    let pass = "correct-horse-9";

    let enc = env
        .cmd()
        .env("OTPFORGE_PASSPHRASE", pass)
        .args(["vault", "encrypt"])
        .output()
        .unwrap();
    assert!(enc.status.success());
    let raw = std::fs::read_to_string(&env.vault).unwrap();
    assert!(raw.contains("ciphertext") && !raw.contains(RFC_SECRET) && !raw.contains("pypi"));

    // works with the passphrase
    let ok = env
        .cmd()
        .env("OTPFORGE_PASSPHRASE", pass)
        .args(["code", "pypi", "--time", "59"])
        .output()
        .unwrap();
    assert_eq!(out(&ok).trim(), "94287082");
    // fails without it (non-interactive) and with a wrong one
    assert_eq!(env.run(&["pypi"]).status.code(), Some(2));
    let wrong = env
        .cmd()
        .env("OTPFORGE_PASSPHRASE", "wrong-passphrase")
        .arg("pypi")
        .output()
        .unwrap();
    assert_eq!(wrong.status.code(), Some(2));
    // adding to an encrypted vault keeps it encrypted
    let add = env
        .cmd()
        .env("OTPFORGE_PASSPHRASE", pass)
        .args(["add", "second", RFC_SECRET])
        .output()
        .unwrap();
    assert!(add.status.success());
    assert!(std::fs::read_to_string(&env.vault)
        .unwrap()
        .contains("ciphertext"));
    // too-short passphrases are rejected
    let env2 = Env::new("enc2");
    env2.run(&["add", "x", RFC_SECRET]);
    let short = env2
        .cmd()
        .env("OTPFORGE_PASSPHRASE", "short")
        .args(["vault", "encrypt"])
        .output()
        .unwrap();
    assert_eq!(short.status.code(), Some(2));

    let dec = env
        .cmd()
        .env("OTPFORGE_PASSPHRASE", pass)
        .args(["vault", "decrypt"])
        .output()
        .unwrap();
    assert!(dec.status.success());
    assert!(std::fs::read_to_string(&env.vault)
        .unwrap()
        .contains("\"encrypted\": false"));
    assert!(env.run(&["pypi"]).status.success());
}

#[test]
fn generate_save_and_list_codes() {
    let env = Env::new("gen");
    let gen = env.run(&[
        "generate",
        "me@x.com",
        "-i",
        "Svc",
        "--save",
        "svc",
        "--backup-codes",
        "0",
    ]);
    assert!(gen.status.success());
    assert!(out(&gen).contains("Saved as:   svc"));
    let list = env.run(&["list", "--codes"]);
    let text = out(&list);
    assert!(text.contains("CODE") && text.contains("svc"));
    let exists = env.run(&["generate", "me@x.com", "--save", "svc"]);
    assert_eq!(exists.status.code(), Some(2));
    assert!(env.run(&["vault", "path"]).status.success());
}

#[cfg(unix)]
#[test]
fn vault_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new("perm");
    env.run(&["add", "pypi", RFC_SECRET]);
    let mode = std::fs::metadata(&env.vault).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn otp_alias_binary_works() {
    let version = Command::new(env!("CARGO_BIN_EXE_otp"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success());
    let env = Env::new("alias");
    env.run(&["add", "pypi", PYPI_URI]);
    let out = Command::new(env!("CARGO_BIN_EXE_otp"))
        .env("OTPFORGE_VAULT", &env.vault)
        .args(["code", "pypi", "--time", "59"])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "94287082");
}

#[cfg(target_os = "linux")]
#[test]
fn copy_flag_uses_clipboard_tool() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new("clip");
    env.run(&["add", "pypi", PYPI_URI]);

    let bin_dir = env.dir.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let sink = env.dir.join("clipboard.txt");
    let tool = bin_dir.join("xclip");
    std::fs::write(&tool, "#!/bin/sh\ncat > \"$OTPFORGE_TEST_CLIP\"\n").unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();

    let run = |args: &[&str]| {
        env.cmd()
            .env("PATH", format!("{}:/usr/bin:/bin", bin_dir.display()))
            .env("OTPFORGE_TEST_CLIP", &sink)
            .env_remove("WAYLAND_DISPLAY")
            .args(args)
            .output()
            .unwrap()
    };

    // NAME shorthand, flag after the name
    let o = run(&["pypi", "-c"]);
    assert!(o.status.success());
    let printed = out(&o).trim().to_owned();
    assert_eq!(std::fs::read_to_string(&sink).unwrap(), printed);

    // flag before the name, and `code NAME -c`
    std::fs::remove_file(&sink).unwrap();
    assert!(run(&["-c", "pypi"]).status.success());
    assert_eq!(std::fs::read_to_string(&sink).unwrap(), printed);
    std::fs::remove_file(&sink).unwrap();
    let o = run(&["code", "pypi", "--time", "59", "-c"]);
    assert!(o.status.success());
    assert_eq!(std::fs::read_to_string(&sink).unwrap(), "94287082");

    // `add -c` copies the first code
    std::fs::remove_file(&sink).unwrap();
    assert!(run(&["add", "second", PYPI_URI, "-c"]).status.success());
    assert_eq!(std::fs::read_to_string(&sink).unwrap().len(), 8);

    // no clipboard tool: code is still printed, exit status is 2
    let o = env
        .cmd()
        .env("PATH", "/nonexistent")
        .env_remove("WAYLAND_DISPLAY")
        .args(["pypi", "-c"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(out(&o).trim().len(), 8);

    // -c before a subcommand is rejected
    assert_eq!(run(&["-c", "list"]).status.code(), Some(2));
}
