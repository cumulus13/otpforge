// File: src\main.rs
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-10-28
// Description: `otpforge` command-line interface.
// License: MIT

//! `otpforge` command-line interface.

use std::fs::OpenOptions;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use clap_color_help::default_styles;
use clap_version_flag::colorful_version;
use serde::Serialize;
use zeroize::Zeroizing;

use otpforge::otp::{self, Algorithm, TotpParams};
use otpforge::secret::{Secret, DEFAULT_SECRET_BYTES, MAX_SECRET_BYTES, MIN_SECRET_BYTES};
use otpforge::vault::{self, Entry, Vault};
use otpforge::{backup, qr, uri, Error, Result};

/// Secure 2FA (TOTP) authenticator and secret key generator.
///
/// Save an account once with `otpforge add NAME`, then run `otpforge NAME`
/// whenever you need a login code.
#[derive(Parser, Debug)]
#[command(
    name = "otpforge",
    version,
    author,
    about,
    propagate_version = true,
    styles=default_styles(),
    after_help = "Examples:\n  otpforge add pypi 'otpauth://totp/PyPI:me?secret=...'   save an account (secret or URI)\n  otpforge pypi                                           print the current login code\n  otpforge list --codes                                   show all accounts with codes"
)]
struct Cli {
    /// Vault file holding saved accounts [default: <config dir>/otpforge/vault.json]
    #[arg(long, global = true, env = "OTPFORGE_VAULT", value_name = "PATH")]
    vault: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Save an account (Base32 secret or otpauth:// URI from the QR code)
    Add(AddArgs),
    /// List saved accounts
    #[command(visible_alias = "ls")]
    List(ListArgs),
    /// Remove a saved account
    #[command(visible_alias = "rm")]
    Remove(RemoveArgs),
    /// Print the otpauth:// URI (and optionally the QR code) of a saved account
    Export(ExportArgs),
    /// Generate a new 2FA secret with provisioning URI, QR code and backup codes
    Generate(GenerateArgs),
    /// Print the current one-time code for a saved account or a secret
    Code(CodeArgs),
    /// Verify a one-time code (exit status 0 = valid, 1 = invalid)
    Verify(VerifyArgs),
    /// Manage the vault file (location, encryption)
    #[command(subcommand)]
    Vault(VaultCommand),
    /// Print a shell completion script
    Completions {
        /// Target shell
        #[arg(value_enum)]
        shell: Shell,
    },
    /// `otpforge NAME` prints the current code of the saved account NAME
    #[command(external_subcommand)]
    External(Vec<String>),
}

#[derive(Subcommand, Debug)]
enum VaultCommand {
    /// Print the vault file location
    Path,
    /// Encrypt the vault with a passphrase (Argon2id + ChaCha20-Poly1305)
    Encrypt,
    /// Remove encryption from the vault
    Decrypt,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AlgorithmArg {
    Sha1,
    Sha256,
    Sha512,
}

impl From<AlgorithmArg> for Algorithm {
    fn from(a: AlgorithmArg) -> Self {
        match a {
            AlgorithmArg::Sha1 => Algorithm::Sha1,
            AlgorithmArg::Sha256 => Algorithm::Sha256,
            AlgorithmArg::Sha512 => Algorithm::Sha512,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Args, Debug)]
struct OtpArgs {
    /// HMAC algorithm (sha1 is the only one every authenticator app supports)
    #[arg(long, value_enum, default_value_t = AlgorithmArg::Sha1)]
    algorithm: AlgorithmArg,
    /// Number of digits per code
    #[arg(long, default_value_t = 6, value_parser = clap::value_parser!(u32).range(6..=8))]
    digits: u32,
    /// Time step in seconds
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=3600))]
    period: u64,
}

impl OtpArgs {
    fn params(&self) -> Result<TotpParams> {
        TotpParams::new(self.algorithm.into(), self.digits, self.period)
    }
}

#[derive(Args, Debug)]
struct SecretSource {
    /// Base32 secret (prefer --secret-stdin or the environment variable: arguments
    /// are visible in process listings and shell history)
    #[arg(long, env = "OTPFORGE_SECRET", hide_env_values = true)]
    secret: Option<String>,
    /// Read the Base32 secret from the first line of standard input
    #[arg(long, conflicts_with = "name")]
    secret_stdin: bool,
}

#[derive(Args, Debug)]
struct AddArgs {
    /// Name to save the account under, e.g. `pypi`
    name: String,
    /// Base32 secret or otpauth:// URI (omit to be prompted without echo, or to read stdin)
    input: Option<String>,
    /// Service name (default: taken from the URI)
    #[arg(short, long)]
    issuer: Option<String>,
    /// Account / user name at the service (default: taken from the URI)
    #[arg(long)]
    account: Option<String>,
    /// HMAC algorithm (default: from the URI, else sha1)
    #[arg(long, value_enum)]
    algorithm: Option<AlgorithmArg>,
    /// Number of digits (default: from the URI, else 6)
    #[arg(long, value_parser = clap::value_parser!(u32).range(6..=8))]
    digits: Option<u32>,
    /// Time step in seconds (default: from the URI, else 30)
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=3600))]
    period: Option<u64>,
    /// Replace an existing account of the same name
    #[arg(long)]
    force: bool,
}

#[derive(Args, Debug)]
struct ListArgs {
    /// Also show the current code and its remaining validity
    #[arg(short, long)]
    codes: bool,
}

#[derive(Args, Debug)]
struct RemoveArgs {
    /// Exact name of the account
    name: String,
    /// Do not ask for confirmation
    #[arg(short, long)]
    yes: bool,
}

#[derive(Args, Debug)]
struct ExportArgs {
    /// Saved account name
    name: String,
    /// Also print the URI as a QR code in the terminal
    #[arg(long)]
    qr: bool,
    /// Terminal has a light background (inverts QR colours)
    #[arg(long, requires = "qr")]
    qr_light: bool,
}

#[derive(Args, Debug)]
struct GenerateArgs {
    /// Account name (usually an e-mail address or username)
    account: String,
    /// Service name shown in the authenticator app
    #[arg(short, long)]
    issuer: Option<String>,
    /// Also save the new account in the vault under this name
    #[arg(long, value_name = "NAME")]
    save: Option<String>,
    /// Secret size in bytes
    #[arg(
        long,
        default_value_t = DEFAULT_SECRET_BYTES as u32,
        value_parser = clap::value_parser!(u32).range((MIN_SECRET_BYTES as i64)..=(MAX_SECRET_BYTES as i64))
    )]
    bytes: u32,
    /// Number of backup codes to generate (0 disables)
    #[arg(long, default_value_t = backup::DEFAULT_COUNT as u32, value_parser = clap::value_parser!(u32).range(0..=100))]
    backup_codes: u32,
    /// Characters per backup code
    #[arg(long, default_value_t = backup::DEFAULT_LENGTH as u32, value_parser = clap::value_parser!(u32).range(6..=32))]
    backup_length: u32,
    /// Print the QR code to the terminal
    #[arg(long)]
    qr: bool,
    /// Terminal has a light background (inverts QR colours)
    #[arg(long, requires = "qr")]
    qr_light: bool,
    /// Also write the QR code as an SVG file (created with mode 0600 on Unix)
    #[arg(long, value_name = "PATH")]
    qr_svg: Option<PathBuf>,
    /// Overwrite an existing SVG file or saved account
    #[arg(long)]
    force: bool,
    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
    #[command(flatten)]
    otp: OtpArgs,
}

#[derive(Args, Debug)]
struct CodeArgs {
    /// Saved account name (omit to use --secret / --secret-stdin)
    name: Option<String>,
    #[command(flatten)]
    source: SecretSource,
    #[command(flatten)]
    otp: OtpArgs,
    /// Also print the remaining validity of the code
    #[arg(short, long)]
    verbose: bool,
    /// Unix timestamp to use instead of the current time
    #[arg(long)]
    time: Option<u64>,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    /// Saved account name (omit to use --secret / --secret-stdin)
    name: Option<String>,
    /// One-time code to verify
    #[arg(long)]
    code: String,
    /// Accepted clock drift in time steps (each direction)
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(0..=10))]
    window: u32,
    #[command(flatten)]
    source: SecretSource,
    #[command(flatten)]
    otp: OtpArgs,
    /// Unix timestamp to use instead of the current time
    #[arg(long)]
    time: Option<u64>,
}

#[derive(Serialize)]
struct GenerateOutput<'a> {
    account: &'a str,
    issuer: Option<&'a str>,
    secret: String,
    uri: String,
    algorithm: &'static str,
    digits: u32,
    period: u64,
    current_code: String,
    backup_codes: Vec<String>,
    qr_svg: Option<String>,
    saved_as: Option<&'a str>,
}

// ---------------------------------------------------------------- helpers

fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Clock)
}

fn read_line_secret(prompt: &str) -> Result<Zeroizing<String>> {
    if io::stdin().is_terminal() {
        eprint!("{prompt}");
        io::stderr().flush()?;
        let value = rpassword::read_password()?;
        return Ok(Zeroizing::new(value));
    }
    let mut line = Zeroizing::new(String::new());
    io::stdin().lock().read_line(&mut line)?;
    Ok(line)
}

fn ask_passphrase(prompt: &str) -> Result<Zeroizing<String>> {
    if let Ok(p) = std::env::var("OTPFORGE_PASSPHRASE") {
        if !p.is_empty() {
            return Ok(Zeroizing::new(p));
        }
    }
    if !io::stdin().is_terminal() {
        return Err(Error::Vault(
            "passphrase required: set OTPFORGE_PASSPHRASE or run in an interactive terminal".into(),
        ));
    }
    eprint!("{prompt}");
    io::stderr().flush()?;
    let value = rpassword::read_password()?;
    Ok(Zeroizing::new(value))
}

fn new_passphrase() -> Result<Zeroizing<String>> {
    let first = ask_passphrase("New vault passphrase: ")?;
    if std::env::var("OTPFORGE_PASSPHRASE").map_or(true, |p| p.is_empty()) {
        let again = ask_passphrase("Repeat passphrase: ")?;
        if *first != *again {
            return Err(Error::Vault("passphrases do not match".into()));
        }
    }
    Ok(first)
}

fn vault_path(cli: &Cli) -> Result<PathBuf> {
    match &cli.vault {
        Some(p) => Ok(p.clone()),
        None => Vault::default_path(),
    }
}

fn load_vault(path: &Path) -> Result<Vault> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.permissions().mode() & 0o077 != 0 {
                eprintln!(
                    "warning: {} is accessible by other users; run `chmod 600` on it",
                    path.display()
                );
            }
        }
    }
    Vault::load(path, || ask_passphrase("Vault passphrase: "))
}

fn check_reserved(name: &str) -> Result<()> {
    vault::validate_name(name)?;
    let cmd = Cli::command();
    let reserved = cmd.get_subcommands().any(|c| {
        c.get_name().eq_ignore_ascii_case(name)
            || c.get_all_aliases().any(|a| a.eq_ignore_ascii_case(name))
    }) || name.eq_ignore_ascii_case("help");
    if reserved {
        Err(Error::InvalidName(name.to_owned()))
    } else {
        Ok(())
    }
}

fn read_secret(source: &SecretSource) -> Result<Secret> {
    if source.secret_stdin {
        let line = read_line_secret("Secret: ")?;
        return Secret::from_base32(line.trim());
    }
    match &source.secret {
        Some(s) => Secret::from_base32(s),
        None => Err(Error::MissingSecret),
    }
}

/// Secret and parameters from a saved account or from --secret.
fn resolve(
    name: Option<&str>,
    source: &SecretSource,
    otp_args: &OtpArgs,
    vault_file: &Path,
) -> Result<(Secret, TotpParams)> {
    match name {
        Some(name) => {
            let vault = load_vault(vault_file)?;
            let entry = vault.find(name)?;
            Ok((entry.secret()?, entry.params()?))
        }
        None => Ok((read_secret(source)?, otp_args.params()?)),
    }
}

fn write_private(path: &Path, contents: &str, force: bool) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            Error::OutputExists(path.display().to_string())
        } else {
            Error::Io(e)
        }
    })?;
    file.write_all(contents.as_bytes())?;
    file.flush()?;
    Ok(())
}

fn print_code(entry: &Entry, now: u64, verbose: bool) -> Result<()> {
    let code = entry.code(now)?;
    let remaining = otp::seconds_remaining(now, entry.period);
    let mut out = io::stdout().lock();
    if verbose {
        writeln!(out, "{code} (valid for {remaining}s)")?;
    } else {
        writeln!(out, "{code}")?;
        if io::stderr().is_terminal() {
            eprintln!("valid for {remaining}s");
        }
    }
    Ok(())
}

// --------------------------------------------------------------- commands

fn add(args: &AddArgs, path: &Path) -> Result<()> {
    check_reserved(&args.name)?;
    let input = match &args.input {
        Some(s) => Zeroizing::new(s.clone()),
        None => read_line_secret("Secret or otpauth:// URI: ")?,
    };
    let input = input.trim();
    if input.is_empty() {
        return Err(Error::MissingSecret);
    }
    let (secret, issuer, account, mut params) = if input
        .get(..10)
        .is_some_and(|p| p.eq_ignore_ascii_case("otpauth://"))
    {
        let parsed = uri::parse_totp_uri(input)?;
        (parsed.secret, parsed.issuer, parsed.account, parsed.params)
    } else {
        (
            Secret::from_base32(input)?,
            None,
            None,
            TotpParams::default(),
        )
    };
    if let Some(a) = args.algorithm {
        params.algorithm = a.into();
    }
    if let Some(d) = args.digits {
        params.digits = d;
    }
    if let Some(p) = args.period {
        params.period = p;
    }
    let now = unix_now()?;
    let entry = Entry::new(
        &args.name,
        &secret,
        args.issuer.as_deref().or(issuer.as_deref()),
        args.account.as_deref().or(account.as_deref()),
        params,
        now,
    )?;
    let mut vault = load_vault(path)?;
    vault.add(entry.clone(), args.force)?;
    vault.save(path)?;

    let mut out = io::stdout().lock();
    writeln!(
        out,
        "Added '{}'{}.",
        entry.name,
        if vault.is_encrypted() {
            " (vault is encrypted)"
        } else {
            ""
        }
    )?;
    writeln!(
        out,
        "Current code: {} (valid for {}s)",
        entry.code(now)?,
        otp::seconds_remaining(now, entry.period)
    )?;
    Ok(())
}

fn list(args: &ListArgs, path: &Path) -> Result<()> {
    let vault = load_vault(path)?;
    if vault.entries().is_empty() {
        eprintln!("No accounts saved. Add one with `otpforge add NAME`.");
        return Ok(());
    }
    let now = unix_now()?;
    let rows: Vec<[String; 5]> = vault
        .entries()
        .iter()
        .map(|e| {
            let (code, ttl) = if args.codes {
                (
                    e.code(now).unwrap_or_else(|_| "error".into()),
                    format!("{}s", otp::seconds_remaining(now, e.period)),
                )
            } else {
                (String::new(), String::new())
            };
            [
                e.name.clone(),
                e.issuer.clone().unwrap_or_default(),
                e.account.clone().unwrap_or_default(),
                code,
                ttl,
            ]
        })
        .collect();
    let headers = ["NAME", "ISSUER", "ACCOUNT", "CODE", "TTL"];
    let cols = if args.codes { 5 } else { 3 };
    let widths: Vec<usize> = (0..cols)
        .map(|i| {
            rows.iter()
                .map(|r| r[i].chars().count())
                .chain(std::iter::once(headers[i].len()))
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut out = io::stdout().lock();
    let line = |cells: Vec<&str>| -> String {
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{c:<w$}", w = widths[i]))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_owned()
    };
    writeln!(out, "{}", line(headers[..cols].to_vec()))?;
    for r in &rows {
        writeln!(
            out,
            "{}",
            line(r[..cols].iter().map(String::as_str).collect())
        )?;
    }
    Ok(())
}

fn remove(args: &RemoveArgs, path: &Path) -> Result<()> {
    let mut vault = load_vault(path)?;
    let name = vault
        .entries()
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case(&args.name))
        .map(|e| e.name.clone())
        .ok_or_else(|| Error::EntryNotFound(args.name.clone()))?;
    if !args.yes {
        if !io::stdin().is_terminal() {
            return Err(Error::Usage(
                "refusing to remove without confirmation: pass --yes".into(),
            ));
        }
        eprint!("Remove '{name}'? You may lose access to the service. [y/N] ");
        io::stderr().flush()?;
        let mut answer = String::new();
        io::stdin().lock().read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }
    vault.remove(&name)?;
    vault.save(path)?;
    println!("Removed '{name}'.");
    Ok(())
}

fn export(args: &ExportArgs, path: &Path) -> Result<()> {
    let vault = load_vault(path)?;
    let entry = vault.find(&args.name)?;
    let provisioning = entry.uri()?;
    let mut out = io::stdout().lock();
    writeln!(out, "{provisioning}")?;
    if args.qr {
        writeln!(
            out,
            "\n{}",
            qr::render_terminal(&provisioning, args.qr_light)?
        )?;
    }
    Ok(())
}

fn show(name: &str, path: &Path) -> Result<()> {
    let vault = load_vault(path)?;
    let entry = vault.find(name)?;
    print_code(entry, unix_now()?, false)
}

fn code(args: &CodeArgs, path: &Path) -> Result<()> {
    let now = match args.time {
        Some(t) => t,
        None => unix_now()?,
    };
    if let Some(name) = &args.name {
        let vault = load_vault(path)?;
        return print_code(vault.find(name)?, now, args.verbose);
    }
    let secret = read_secret(&args.source)?;
    let params = args.otp.params()?;
    let value = otp::totp(&secret, now, &params)?;
    let mut out = io::stdout().lock();
    if args.verbose {
        writeln!(
            out,
            "{value} (valid for {}s)",
            otp::seconds_remaining(now, params.period)
        )?;
    } else {
        writeln!(out, "{value}")?;
    }
    Ok(())
}

fn verify(args: &VerifyArgs, path: &Path) -> Result<ExitCode> {
    let (secret, params) = resolve(args.name.as_deref(), &args.source, &args.otp, path)?;
    let now = match args.time {
        Some(t) => t,
        None => unix_now()?,
    };
    let mut out = io::stdout().lock();
    match otp::verify(&secret, &args.code, now, &params, args.window)? {
        Some(offset) => {
            writeln!(out, "valid (step offset: {offset})")?;
            Ok(ExitCode::SUCCESS)
        }
        None => {
            writeln!(out, "invalid")?;
            Ok(ExitCode::from(1))
        }
    }
}

fn generate(args: &GenerateArgs, vault_file: &Path) -> Result<()> {
    if args.qr && matches!(args.format, Format::Json) {
        return Err(Error::Usage(
            "--qr cannot be combined with --format json (use --qr-svg instead)".into(),
        ));
    }
    if let Some(name) = &args.save {
        check_reserved(name)?;
    }
    let params = args.otp.params()?;
    let secret = Secret::generate(args.bytes as usize)?;
    let issuer = args.issuer.as_deref().map(str::trim);
    let account = args.account.trim();
    let provisioning = uri::totp_uri(&secret, account, issuer, &params)?;
    let now = unix_now()?;
    let code = otp::totp(&secret, now, &params)?;
    let backup_codes = if args.backup_codes > 0 {
        backup::generate(args.backup_codes as usize, args.backup_length as usize)?
    } else {
        Vec::new()
    };

    if let Some(name) = &args.save {
        let entry = Entry::new(name, &secret, issuer, Some(account), params, now)?;
        let mut vault = load_vault(vault_file)?;
        vault.add(entry, args.force)?;
        vault.save(vault_file)?;
    }
    if let Some(path) = &args.qr_svg {
        write_private(path, &qr::render_svg(&provisioning)?, args.force)?;
    }

    let mut out = io::stdout().lock();
    match args.format {
        Format::Json => {
            let payload = GenerateOutput {
                account,
                issuer,
                secret: secret.to_base32(),
                uri: provisioning,
                algorithm: params.algorithm.as_str(),
                digits: params.digits,
                period: params.period,
                current_code: code,
                backup_codes,
                qr_svg: args.qr_svg.as_ref().map(|p| p.display().to_string()),
                saved_as: args.save.as_deref(),
            };
            serde_json::to_writer_pretty(&mut out, &payload).map_err(io::Error::other)?;
            writeln!(out)?;
        }
        Format::Text => {
            writeln!(out, "Account:    {account}")?;
            if let Some(issuer) = issuer {
                writeln!(out, "Issuer:     {issuer}")?;
            }
            writeln!(out, "Secret:     {}", secret.to_base32())?;
            writeln!(out, "URI:        {provisioning}")?;
            writeln!(
                out,
                "Parameters: {}, {} digits, {}s period",
                params.algorithm, params.digits, params.period
            )?;
            writeln!(
                out,
                "Current:    {code} (valid for {}s)",
                otp::seconds_remaining(now, params.period)
            )?;
            if let Some(name) = &args.save {
                writeln!(out, "Saved as:   {name}  (run `otpforge {name}` for codes)")?;
            }
            if let Some(path) = &args.qr_svg {
                writeln!(out, "QR (SVG):   {}", path.display())?;
            }
            if !backup_codes.is_empty() {
                writeln!(out, "\nBackup codes (store offline, each works once):")?;
                for (i, c) in backup_codes.iter().enumerate() {
                    writeln!(out, "  {:>3}. {c}", i + 1)?;
                }
            }
            if args.qr {
                writeln!(
                    out,
                    "\n{}",
                    qr::render_terminal(&provisioning, args.qr_light)?
                )?;
            }
        }
    }
    out.flush()?;
    Ok(())
}

fn vault_cmd(cmd: &VaultCommand, path: &Path) -> Result<()> {
    match cmd {
        VaultCommand::Path => {
            println!("{}", path.display());
            Ok(())
        }
        VaultCommand::Encrypt => {
            let mut vault = load_vault(path)?;
            if vault.is_encrypted() {
                return Err(Error::Vault("vault is already encrypted".into()));
            }
            vault.set_passphrase(Some(new_passphrase()?))?;
            vault.save(path)?;
            println!("Vault encrypted: {}", path.display());
            Ok(())
        }
        VaultCommand::Decrypt => {
            let mut vault = load_vault(path)?;
            if !vault.is_encrypted() {
                return Err(Error::Vault("vault is not encrypted".into()));
            }
            vault.set_passphrase(None)?;
            vault.save(path)?;
            println!(
                "Vault decrypted (now protected by file permissions only): {}",
                path.display()
            );
            Ok(())
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    if let Command::Completions { shell } = &cli.command {
        let mut cmd = Cli::command();
        clap_complete::generate(*shell, &mut cmd, "otpforge", &mut io::stdout());
        return Ok(ExitCode::SUCCESS);
    }
    let path = vault_path(&cli)?;
    match &cli.command {
        Command::Add(a) => add(a, &path)?,
        Command::List(a) => list(a, &path)?,
        Command::Remove(a) => remove(a, &path)?,
        Command::Export(a) => export(a, &path)?,
        Command::Generate(a) => generate(a, &path)?,
        Command::Code(a) => code(a, &path)?,
        Command::Verify(a) => return verify(a, &path),
        Command::Vault(c) => vault_cmd(c, &path)?,
        Command::External(args) => match args.as_slice() {
            [name] => show(name, &path)?,
            _ => return Err(Error::Usage(
                "unknown command; run `otpforge --help` (or `otpforge NAME` for a saved account)"
                    .into(),
            )),
        },
        Command::Completions { .. } => unreachable!("handled above"),
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && (args[1] == "-V" || args[1] == "--version") {
        let version = colorful_version!();
        version.print_and_exit();
    }
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(Error::Io(e)) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
