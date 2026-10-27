//! Persistent account vault with optional passphrase encryption.
//!
//! The vault is a single JSON file. In *plaintext* mode it is protected only by
//! file permissions (`0600` on Unix). In *encrypted* mode the account list is
//! sealed with ChaCha20-Poly1305 under a key derived from the passphrase with
//! Argon2id; salt and nonce are regenerated on every save.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use argon2::{Algorithm as KdfAlgorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::otp::{self, Algorithm, TotpParams};
use crate::secret::Secret;
use crate::uri;

const FORMAT_VERSION: u32 = 1;
const AAD: &[u8] = b"otpforge-vault-v1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[cfg(not(test))]
const KDF_M_COST: u32 = 65_536; // 64 MiB
#[cfg(test)]
const KDF_M_COST: u32 = 64;
#[cfg(not(test))]
const KDF_T_COST: u32 = 3;
#[cfg(test)]
const KDF_T_COST: u32 = 1;
const KDF_P_COST: u32 = 1;

// Upper bounds protect against a tampered file forcing huge allocations.
const MAX_M_COST: u32 = 1_048_576;
const MAX_T_COST: u32 = 16;
const MAX_P_COST: u32 = 16;

/// Minimum accepted passphrase length.
pub const MIN_PASSPHRASE_LEN: usize = 8;

/// Validates an account name: 1–64 characters of `A-Z a-z 0-9 . _ @ -`,
/// not starting with `-`.
pub fn validate_name(name: &str) -> Result<()> {
    let ok = (1..=64).contains(&name.len())
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidName(name.to_owned()))
    }
}

/// A saved account.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    /// Short unique name used on the command line.
    #[zeroize(skip)]
    pub name: String,
    /// Service name (e.g. `PyPI`).
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Account / user name at the service.
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    secret: String,
    /// HMAC algorithm.
    #[zeroize(skip)]
    pub algorithm: Algorithm,
    /// Digits per code.
    #[zeroize(skip)]
    pub digits: u32,
    /// Time step in seconds.
    #[zeroize(skip)]
    pub period: u64,
    /// Creation time (Unix seconds).
    #[zeroize(skip)]
    pub created: u64,
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("name", &self.name)
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Entry {
    /// Creates and validates an entry.
    pub fn new(
        name: &str,
        secret: &Secret,
        issuer: Option<&str>,
        account: Option<&str>,
        params: TotpParams,
        created: u64,
    ) -> Result<Self> {
        validate_name(name)?;
        params.validate()?;
        let clean = |v: Option<&str>| {
            v.map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        let entry = Self {
            name: name.to_owned(),
            issuer: clean(issuer),
            account: clean(account),
            secret: secret.to_base32(),
            algorithm: params.algorithm,
            digits: params.digits,
            period: params.period,
            created,
        };
        entry.uri()?; // validates issuer/account labels
        Ok(entry)
    }

    /// The entry's secret.
    pub fn secret(&self) -> Result<Secret> {
        Secret::from_base32(&self.secret)
    }

    /// The entry's TOTP parameters.
    pub fn params(&self) -> Result<TotpParams> {
        TotpParams::new(self.algorithm, self.digits, self.period)
    }

    /// Provisioning URI (contains the secret).
    pub fn uri(&self) -> Result<String> {
        uri::totp_uri(
            &self.secret()?,
            self.account.as_deref().unwrap_or(&self.name),
            self.issuer.as_deref(),
            &self.params()?,
        )
    }

    /// One-time code valid at `unix_time`.
    pub fn code(&self, unix_time: u64) -> Result<String> {
        otp::totp(&self.secret()?, unix_time, &self.params()?)
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct Kdf {
    algorithm: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: String,
}

#[derive(Serialize, Deserialize)]
struct FileFormat {
    version: u32,
    encrypted: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    entries: Vec<Entry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf: Option<Kdf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ciphertext: Option<String>,
}

fn vault_err<E: fmt::Display>(context: &str) -> impl FnOnce(E) -> Error + '_ {
    move |e| Error::Vault(format!("{context}: {e}"))
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    m: u32,
    t: u32,
    p: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(m, t, p, Some(32)).map_err(vault_err("invalid KDF parameters"))?;
    let argon = Argon2::new(KdfAlgorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt, &mut *key)
        .map_err(vault_err("key derivation failed"))?;
    Ok(key)
}

fn decode_field(value: Option<&String>, what: &str) -> Result<Vec<u8>> {
    let value = value.ok_or_else(|| Error::Vault(format!("missing {what}")))?;
    BASE64
        .decode(value.as_bytes())
        .map_err(|e| Error::Vault(format!("invalid {what}: {e}")))
}

fn decrypt(file: &FileFormat, passphrase: &str) -> Result<Vec<Entry>> {
    let kdf = file
        .kdf
        .as_ref()
        .ok_or_else(|| Error::Vault("missing kdf header".into()))?;
    if kdf.algorithm != "argon2id" {
        return Err(Error::Vault(format!("unsupported KDF '{}'", kdf.algorithm)));
    }
    if kdf.m_cost > MAX_M_COST || kdf.t_cost > MAX_T_COST || kdf.p_cost > MAX_P_COST {
        return Err(Error::Vault("KDF parameters exceed safe limits".into()));
    }
    let salt = BASE64
        .decode(kdf.salt.as_bytes())
        .map_err(vault_err("invalid salt"))?;
    let nonce: [u8; NONCE_LEN] = decode_field(file.nonce.as_ref(), "nonce")?
        .try_into()
        .map_err(|_| Error::Vault("invalid nonce length".into()))?;
    let ciphertext = decode_field(file.ciphertext.as_ref(), "ciphertext")?;

    let key = derive_key(
        passphrase.as_bytes(),
        &salt,
        kdf.m_cost,
        kdf.t_cost,
        kdf.p_cost,
    )?;
    let cipher = ChaCha20Poly1305::new_from_slice(&*key).map_err(vault_err("cipher setup"))?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &ciphertext,
                    aad: AAD,
                },
            )
            .map_err(|_| Error::Vault("wrong passphrase or corrupted vault".into()))?,
    );
    Ok(serde_json::from_slice(&plain)?)
}

fn encrypt(entries: &[Entry], passphrase: &str) -> Result<FileFormat> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|e| Error::Rng(e.to_string()))?;
    getrandom::fill(&mut nonce).map_err(|e| Error::Rng(e.to_string()))?;
    let key = derive_key(
        passphrase.as_bytes(),
        &salt,
        KDF_M_COST,
        KDF_T_COST,
        KDF_P_COST,
    )?;
    let cipher = ChaCha20Poly1305::new_from_slice(&*key).map_err(vault_err("cipher setup"))?;
    let plain = Zeroizing::new(serde_json::to_vec(entries)?);
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &plain,
                aad: AAD,
            },
        )
        .map_err(|_| Error::Vault("encryption failed".into()))?;
    Ok(FileFormat {
        version: FORMAT_VERSION,
        encrypted: true,
        entries: Vec::new(),
        kdf: Some(Kdf {
            algorithm: "argon2id".into(),
            m_cost: KDF_M_COST,
            t_cost: KDF_T_COST,
            p_cost: KDF_P_COST,
            salt: BASE64.encode(&salt),
        }),
        nonce: Some(BASE64.encode(&nonce)),
        ciphertext: Some(BASE64.encode(&ciphertext)),
    })
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !dir.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(dir)?;
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| Error::Vault("vault path has no file name".into()))?
        .to_string_lossy();
    let tmp = dir.join(format!(".{file_name}.tmp-{}", std::process::id()));
    let _ = fs::remove_file(&tmp);

    let result = (|| -> io::Result<()> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    Ok(result?)
}

/// The account vault.
#[derive(Default)]
pub struct Vault {
    entries: Vec<Entry>,
    passphrase: Option<Zeroizing<String>>,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("entries", &self.entries.len())
            .field("encrypted", &self.is_encrypted())
            .finish()
    }
}

impl Vault {
    /// Default vault location inside the user's configuration directory.
    pub fn default_path() -> Result<PathBuf> {
        dirs::config_dir()
            .map(|d| d.join("otpforge").join("vault.json"))
            .ok_or_else(|| {
                Error::Vault("cannot determine the configuration directory; use --vault".into())
            })
    }

    /// Creates an empty plaintext vault.
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads the vault at `path`. A missing file yields an empty vault.
    /// `ask_passphrase` is only called when the file is encrypted.
    pub fn load<F>(path: &Path, ask_passphrase: F) -> Result<Self>
    where
        F: FnOnce() -> Result<Zeroizing<String>>,
    {
        let raw = match fs::read(path) {
            Ok(raw) => Zeroizing::new(raw),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(e) => return Err(e.into()),
        };
        let file: FileFormat = serde_json::from_slice(&raw)
            .map_err(|e| Error::Vault(format!("{} is not a valid vault: {e}", path.display())))?;
        if file.version != FORMAT_VERSION {
            return Err(Error::Vault(format!(
                "unsupported vault version {} (this build supports {FORMAT_VERSION})",
                file.version
            )));
        }
        if file.encrypted {
            let passphrase = ask_passphrase()?;
            let entries = decrypt(&file, &passphrase)?;
            Ok(Self {
                entries,
                passphrase: Some(passphrase),
            })
        } else {
            Ok(Self {
                entries: file.entries,
                passphrase: None,
            })
        }
    }

    /// Writes the vault atomically (temp file + rename, mode `0600`).
    pub fn save(&self, path: &Path) -> Result<()> {
        let file = match &self.passphrase {
            Some(p) => encrypt(&self.entries, p)?,
            None => FileFormat {
                version: FORMAT_VERSION,
                encrypted: false,
                entries: self.entries.clone(),
                kdf: None,
                nonce: None,
                ciphertext: None,
            },
        };
        let bytes = Zeroizing::new(serde_json::to_vec_pretty(&file)?);
        atomic_write(path, &bytes)
    }

    /// Whether saving will encrypt the vault.
    pub fn is_encrypted(&self) -> bool {
        self.passphrase.is_some()
    }

    /// Enables encryption with `passphrase`, or disables it with `None`.
    pub fn set_passphrase(&mut self, passphrase: Option<Zeroizing<String>>) -> Result<()> {
        if let Some(p) = &passphrase {
            if p.chars().count() < MIN_PASSPHRASE_LEN {
                return Err(Error::Vault(format!(
                    "passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
                )));
            }
        }
        self.passphrase = passphrase;
        Ok(())
    }

    /// All entries, sorted by name.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Adds an entry; with `replace` an existing entry of the same name is overwritten.
    pub fn add(&mut self, entry: Entry, replace: bool) -> Result<()> {
        match self
            .entries
            .iter()
            .position(|e| e.name.eq_ignore_ascii_case(&entry.name))
        {
            Some(i) if replace => self.entries[i] = entry,
            Some(_) => return Err(Error::EntryExists(entry.name.clone())),
            None => self.entries.push(entry),
        }
        self.entries.sort_by_key(|e| e.name.to_ascii_lowercase());
        Ok(())
    }

    /// Removes the entry named exactly `name` (case-insensitive).
    pub fn remove(&mut self, name: &str) -> Result<Entry> {
        let i = self
            .entries
            .iter()
            .position(|e| e.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| Error::EntryNotFound(name.to_owned()))?;
        Ok(self.entries.remove(i))
    }

    /// Finds an entry by exact name, or by unique case-insensitive prefix.
    pub fn find(&self, query: &str) -> Result<&Entry> {
        if let Some(e) = self
            .entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(query))
        {
            return Ok(e);
        }
        let q = query.to_ascii_lowercase();
        let matches: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| !q.is_empty() && e.name.to_ascii_lowercase().starts_with(&q))
            .collect();
        match matches.as_slice() {
            [] => Err(Error::EntryNotFound(query.to_owned())),
            [one] => Ok(one),
            many => Err(Error::AmbiguousEntry {
                query: query.to_owned(),
                matches: many
                    .iter()
                    .map(|e| e.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn tmp_path() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir()
            .join(format!("otpforge-vault-test-{}-{n}", std::process::id()))
            .join("vault.json")
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    fn entry(name: &str) -> Entry {
        let secret = Secret::from_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        Entry::new(
            name,
            &secret,
            Some("PyPI"),
            Some("user"),
            TotpParams::default(),
            1,
        )
        .unwrap()
    }

    fn no_prompt() -> Result<Zeroizing<String>> {
        panic!("passphrase must not be requested");
    }

    fn pass(p: &str) -> impl FnOnce() -> Result<Zeroizing<String>> + '_ {
        move || Ok(Zeroizing::new(p.to_owned()))
    }

    #[test]
    fn missing_file_is_empty_vault() {
        let path = tmp_path();
        let v = Vault::load(&path, no_prompt).unwrap();
        assert!(v.entries().is_empty() && !v.is_encrypted());
    }

    #[test]
    fn plaintext_roundtrip() {
        let path = tmp_path();
        let mut v = Vault::new();
        v.add(entry("pypi"), false).unwrap();
        v.add(entry("github"), false).unwrap();
        v.save(&path).unwrap();
        let loaded = Vault::load(&path, no_prompt).unwrap();
        let names: Vec<_> = loaded.entries().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["github", "pypi"]);
        assert_eq!(
            loaded.find("pypi").unwrap().code(59).unwrap(),
            entry("x").code(59).unwrap()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        cleanup(&path);
    }

    #[test]
    fn encrypted_roundtrip_hides_secret() {
        let path = tmp_path();
        let mut v = Vault::new();
        v.add(entry("pypi"), false).unwrap();
        v.set_passphrase(Some(Zeroizing::new("correct horse".into())))
            .unwrap();
        v.save(&path).unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("ciphertext") && !raw.contains("GEZDGNBVGY3TQOJQ"));
        assert!(!raw.contains("pypi"));
        let loaded = Vault::load(&path, pass("correct horse")).unwrap();
        assert!(loaded.is_encrypted());
        assert_eq!(loaded.entries().len(), 1);
        cleanup(&path);
    }

    #[test]
    fn wrong_passphrase_and_tampering_fail() {
        let path = tmp_path();
        let mut v = Vault::new();
        v.add(entry("pypi"), false).unwrap();
        v.set_passphrase(Some(Zeroizing::new("correct horse".into())))
            .unwrap();
        v.save(&path).unwrap();
        assert!(Vault::load(&path, pass("wrong passphrase")).is_err());

        let mut file: FileFormat = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut ct = BASE64
            .decode(file.ciphertext.as_ref().unwrap().as_bytes())
            .unwrap();
        ct[0] ^= 1;
        file.ciphertext = Some(BASE64.encode(&ct));
        fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(Vault::load(&path, pass("correct horse")).is_err());
        cleanup(&path);
    }

    #[test]
    fn rejects_excessive_kdf_parameters() {
        let path = tmp_path();
        let mut v = Vault::new();
        v.add(entry("pypi"), false).unwrap();
        v.set_passphrase(Some(Zeroizing::new("correct horse".into())))
            .unwrap();
        v.save(&path).unwrap();
        let mut file: FileFormat = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        file.kdf.as_mut().unwrap().m_cost = u32::MAX;
        fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(Vault::load(&path, pass("correct horse")).is_err());
        cleanup(&path);
    }

    #[test]
    fn short_passphrase_rejected() {
        let mut v = Vault::new();
        assert!(v
            .set_passphrase(Some(Zeroizing::new("short".into())))
            .is_err());
    }

    #[test]
    fn add_remove_find() {
        let mut v = Vault::new();
        v.add(entry("pypi"), false).unwrap();
        assert!(v.add(entry("PyPI"), false).is_err());
        v.add(entry("PyPI"), true).unwrap();
        assert_eq!(v.entries().len(), 1);
        v.add(entry("pypi-test"), false).unwrap();
        v.add(entry("github"), false).unwrap();
        assert_eq!(v.find("GITHUB").unwrap().name, "github");
        assert_eq!(v.find("gi").unwrap().name, "github");
        assert!(matches!(v.find("py"), Err(Error::AmbiguousEntry { .. })));
        assert_eq!(v.find("pypi").unwrap().name, "PyPI");
        assert!(matches!(v.find("nope"), Err(Error::EntryNotFound(_))));
        assert!(v.remove("pypi-test").is_ok());
        assert!(v.remove("pyp").is_err());
    }

    #[test]
    fn name_validation() {
        for ok in ["pypi", "my.bank_2", "a@b", "x-y"] {
            assert!(validate_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "-x", "a b", "a/b", &"a".repeat(65), "naïve"] {
            assert!(validate_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn debug_never_leaks_secret() {
        assert!(!format!("{:?}", entry("pypi")).contains("GEZDG"));
    }
}
