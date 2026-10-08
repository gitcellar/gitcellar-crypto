//! I-1 — origin signatures over repo-key grants (`gc-grant-v2`).
//!
//! ## The defect this closes (grant integrity rested entirely on TOFU)
//!
//! A repo-key grant is the wrapped repository key, relayed to a collaborator
//! **through the untrusted Cloud**. Before this module, the grant carried NO
//! origin signature: the payload is encrypt-only (the OpenPGP key-grant path
//! explicitly *rejects* an enclosed signature layer — see
//! `encryption.rs`'s `VerificationHelper::check`), so the only thing standing
//! between a collaborator and an attacker-supplied repo key was the receiver's
//! **first-contact TOFU pin** (`key_manager::enforce_repo_key_pin`, P0-4).
//!
//! TOFU is a real defense, but it is a defense with a hole exactly where it
//! matters most: **first contact**. On the very first grant for a
//! `(repo_id, key_version)` there is nothing to compare against, so the
//! receiver pins whatever arrives. Anyone with Cloud write access could
//! therefore substitute their own repo key on a collaborator's first sight of
//! a repo, and that key would be pinned as legitimate — the victim then
//! encrypts future pushes under a key the attacker knows. Every *later* swap
//! was already caught by the pin; the first one was free.
//!
//! ## The fix
//!
//! The granting owner signs a canonical grant tuple with their **identity
//! key**, and the recipient verifies that signature against the granter's cert
//! BEFORE trusting or importing the grant. TOFU stays (it is now
//! defense-in-depth for later versions); what changes is that first contact is
//! no longer unauthenticated. An attacker can no longer fabricate a grant —
//! they must actively sign one, which requires the owner's identity key and,
//! failing that, leaves a non-repudiable forgery attempt.
//!
//! This deliberately does NOT mint a novel scheme. It is the same signed-tuple
//! construction this crate uses for every signed statement:
//! a versioned domain tag, `lp()` length-prefixed fields, a detached OpenPGP
//! signature over the canonical, base64 for transport, and a verifier that
//! treats "absent" exactly like "invalid".
//!
//! ## The canonical (frozen)
//!
//! ```text
//! lp("gc-grant-v2") ‖ lp(repo_uid) ‖ lp(key_version)
//!                   ‖ lp(recipient_fingerprint) ‖ lp(granter_fingerprint)
//!                   ‖ lp(key_material_b64) ‖ lp(timestamp_unix)
//! ```
//!
//! where `lp` is [`crate::canonical::lp_push`] (`<decimal-len>:<bytes>\n`) —
//! the same length-prefix encoder every canonical in this crate uses. The
//! prefixes make the composition injection-safe: no field's contents can be
//! shifted across a boundary to forge a different tuple with the same bytes.
//!
//! **v2 (2026-10).** v1 bound only the repository's
//! `owner/name`, so a grant stopped verifying the moment the repository was
//! renamed or transferred. v2 binds the repository's immutable `repo_uid` and
//! nothing that names it: every verifier passes the uid, so a grant signed
//! before a rename verifies after it. The v1 tag is deleted, not kept as a
//! fallback. A recipient learns
//! which uid a name means from the owner-signed repo-owner binding
//! (`gc-repo-owner-v2`), never from the relay.
//!
//! **Why each field is bound:**
//!
//! - `repo_uid` + `key_version` — a signature over a grant for repo A / v1
//!   cannot be replayed as repo B, or as a later version of the same repo.
//!   The display name is not bound, so a rename touches no grant.
//! - `recipient_fingerprint` — binds the grant to WHO it is for. Without it, a
//!   genuine grant intended for Alice could be relayed to Bob and still verify.
//! - `granter_fingerprint` — binds the claimed author into the signed bytes, so
//!   a signature made by one key cannot be re-presented as another's.
//! - `key_material_b64` — binds the ACTUAL repo key being granted (base64 of the
//!   serialized TSK), not its outer encryption. This is the whole point:
//!   swapping in an attacker's repo key invalidates the signature. Binding the
//!   key itself rather than the wrapped bytes also means the signature survives
//!   re-wrapping and says something about the *key*, which is what the
//!   recipient actually installs.
//! - `timestamp_unix` — issuance time, for audit/ordering.
//!
//! ## Where the signature travels (and why it is inside the ciphertext)
//!
//! The signed tuple + signature ride INSIDE the encrypted grant payload, as a
//! [`GrantBundle`] — the blob the Cloud relays is now
//! `encrypt_to_recipient(json(GrantBundle))` instead of
//! `encrypt_to_recipient(tsk)`. Consequences, all deliberate:
//!
//! - **The Cloud learns nothing new.** No schema column, no route field, no
//!   grant metadata in plaintext. A signature stored server-side would have
//!   told the untrusted relay who granted what to whom; this keeps the relay a
//!   dumb dead-drop, which is the zero-access posture the product claims.
//! - **Verify BEFORE import, not before decrypt.** The recipient decrypts with
//!   its own key (decryption is not a trust action — it is just bytes), parses
//!   the bundle, verifies authorship, and only THEN touches the keyring. The
//!   trust boundary is the import, and the check sits in front of it.
//! - **Old-format grants fail closed.** A pre-I-1 payload (a bare TSK) is not
//!   valid bundle JSON, so it is refused rather than silently imported
//!   unverified. Pre-launch, that is a dev-data reset — by design.
//!
//! ## A delegated grant carries its delegation inside the signed bytes (KTD-6)
//!
//! A grant signed by someone other than the repo owner (an org admin, a
//! collaborator re-sharing) is authorized by an owner-signed delegation. That
//! delegation rides in the bundle as a [`GrantDelegation`], and the granter's
//! signature covers it, under a separate domain tag:
//!
//! ```text
//! lp("gc-grant-delegated-v2") ‖ <the six gc-grant-v2 fields, same order>
//!     ‖ lp(del.repo_uid) ‖ lp(del.delegate_account) ‖ lp(del.delegate_fingerprint)
//!     ‖ lp(del.key_version) ‖ lp(del.timestamp_unix) ‖ lp(del.expires_at_unix)
//!     ‖ lp(del.delegation_sig_b64)
//! ```
//!
//! So a relay that strips the delegation (the canonical falls back to
//! `gc-grant-v2`), swaps it, or edits any field of it breaks the grant signature.
//! A bundle with no delegation signs and verifies under the plain
//! `gc-grant-v2` canonical. This module proves only that the
//! granter authored the grant *with this delegation attached*; whether the
//! delegation authorizes the granter is `authorize_repo_grant`'s decision
//! (key-directory feature), fed by [`GrantBundle::repo_delegation`].

use crate::canonical::lp_push;
use crate::broadcast::verify_detached;
use crate::encryption::EncryptionEngine;
use crate::error::{CryptoError, Result};

/// Versioned domain tag for the grant canonical. Bump ONLY with a coordinated
/// granter+recipient change — old signatures stop verifying (by design).
/// v2 binds the repository's immutable `repo_uid`.
pub const GRANT_CANONICAL_VERSION: &str = "gc-grant-v2";

/// Domain tag for the canonical of a grant that carries a delegation (KTD-6).
/// Distinct from [`GRANT_CANONICAL_VERSION`], so a delegated grant's signature
/// can never verify as a plain grant once its delegation is stripped.
pub const DELEGATED_GRANT_CANONICAL_VERSION: &str = "gc-grant-delegated-v2";

/// Normalize a fingerprint for canonical use: uppercase, whitespace stripped.
///
/// Sequoia renders fingerprints two ways — `Fingerprint::to_hex()` (unspaced
/// uppercase) and `Display` (spaced groups) — and earlier work lost
/// time to picking the wrong one. Rather than
/// depend on every call site choosing identically, both sides normalize here,
/// so a spaced fingerprint and its unspaced twin produce the SAME signed bytes.
pub fn normalize_fingerprint(fingerprint: &str) -> String {
    fingerprint
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(|c| c.to_uppercase())
        .collect()
}

/// The tuple an owner signs when granting a repo key to a collaborator.
///
/// Field values are whatever the granter and recipient can BOTH compute
/// independently — the recipient reconstructs this from the relayed grant plus
/// its own identity, then verifies. See the module docs for the canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoKeyGrant {
    /// The repository's immutable id (`repo_uid`), minted with its first key.
    /// A rename or transfer does not change it, so the grant keeps verifying.
    pub repo_uid: String,
    /// Key version this grant delivers (matches the Cloud's `key_version`).
    pub key_version: i32,
    /// The RECIPIENT's identity-key fingerprint — who this grant is for.
    /// Normalized via [`normalize_fingerprint`].
    pub recipient_fingerprint: String,
    /// The GRANTER's identity-key fingerprint — who authored this grant.
    /// Normalized via [`normalize_fingerprint`].
    pub granter_fingerprint: String,
    /// The repo key being granted: base64 of the serialized TSK (the same bytes
    /// the recipient imports into its keyring). Compared verbatim — never
    /// re-encoded, or the signed bytes would drift from the delivered key.
    pub key_material_b64: String,
    /// Issuance time, unix seconds.
    pub timestamp_unix: i64,
}

impl RepoKeyGrant {
    /// Build a grant tuple for the repository `repo_uid`, normalizing both
    /// fingerprints so the canonical is stable regardless of which Sequoia
    /// rendering the caller had.
    pub fn new(
        repo_uid: impl Into<String>,
        key_version: i32,
        recipient_fingerprint: &str,
        granter_fingerprint: &str,
        key_material_b64: impl Into<String>,
        timestamp_unix: i64,
    ) -> Self {
        RepoKeyGrant {
            repo_uid: repo_uid.into(),
            key_version,
            recipient_fingerprint: normalize_fingerprint(recipient_fingerprint),
            granter_fingerprint: normalize_fingerprint(granter_fingerprint),
            key_material_b64: key_material_b64.into(),
            timestamp_unix,
        }
    }

    /// Deterministic, injection-safe canonical byte string: length-prefixed
    /// fields under a versioned domain tag (mirrors `KeyAssertion::canonical`).
    ///
    /// Fingerprints are normalized here too, so a `RepoKeyGrant` built by
    /// struct literal (rather than [`RepoKeyGrant::new`]) still canonicalizes
    /// identically — the signature must not depend on how the struct was made.
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        lp_push(&mut out, GRANT_CANONICAL_VERSION);
        lp_push(&mut out, &self.repo_uid);
        lp_push(&mut out, &self.key_version.to_string());
        lp_push(&mut out, &normalize_fingerprint(&self.recipient_fingerprint));
        lp_push(&mut out, &normalize_fingerprint(&self.granter_fingerprint));
        lp_push(&mut out, &self.key_material_b64);
        lp_push(&mut out, &self.timestamp_unix.to_string());
        out
    }

    /// The bytes the granter signs for this grant with `delegation` attached.
    /// `None` is exactly [`RepoKeyGrant::canonical`]; `Some` is the
    /// `gc-grant-delegated-v2` canonical in the module docs, which binds every
    /// field of the delegation and its owner signature.
    pub fn canonical_with_delegation(&self, delegation: Option<&GrantDelegation>) -> Vec<u8> {
        let Some(del) = delegation else {
            return self.canonical();
        };
        let mut out = Vec::with_capacity(512);
        lp_push(&mut out, DELEGATED_GRANT_CANONICAL_VERSION);
        lp_push(&mut out, &self.repo_uid);
        lp_push(&mut out, &self.key_version.to_string());
        lp_push(&mut out, &normalize_fingerprint(&self.recipient_fingerprint));
        lp_push(&mut out, &normalize_fingerprint(&self.granter_fingerprint));
        lp_push(&mut out, &self.key_material_b64);
        lp_push(&mut out, &self.timestamp_unix.to_string());
        lp_push(&mut out, &del.repo_uid);
        lp_push(&mut out, &del.delegate_account);
        lp_push(&mut out, &del.delegate_fingerprint);
        lp_push(&mut out, &del.key_version.to_string());
        lp_push(&mut out, &del.timestamp_unix.to_string());
        lp_push(&mut out, &del.expires_at_unix.to_string());
        lp_push(&mut out, &del.delegation_sig_b64);
        out
    }
}

/// An owner-signed repo delegation as it travels inside a [`GrantBundle`]
/// (KTD-6): the fields of `repo_owner::RepoDelegation` plus the owner's
/// base64 detached signature over that delegation's canonical.
///
/// Carried verbatim (never re-normalized in the grant canonical), so what the
/// granter signed is byte-for-byte what the recipient reads. Build one with
/// `RepoDelegation::to_bundled` and read it back with
/// [`GrantBundle::repo_delegation`] (both key-directory feature).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GrantDelegation {
    /// The repository the delegation is for: its immutable `repo_uid`, so a
    /// rename does not void a delegation.
    pub repo_uid: String,
    /// The delegate's account (lowercased), as in the delegation.
    pub delegate_account: String,
    /// The delegate's identity fingerprint (normalized) — must be the granter.
    pub delegate_fingerprint: String,
    /// The one repo-key version the delegation covers (KTD-7).
    pub key_version: u32,
    /// Delegation issuance time, unix seconds.
    pub timestamp_unix: i64,
    /// Delegation expiry, unix seconds.
    pub expires_at_unix: i64,
    /// Base64 detached signature over the delegation's canonical, by the repo
    /// owner's identity key.
    pub delegation_sig_b64: String,
}

/// Sign a [`RepoKeyGrant`] with the granting owner's identity (detached OpenPGP
/// signature over the canonical), returning base64 for transport.
///
/// `engine` MUST hold the granter's identity secret key.
pub fn sign_repo_key_grant(engine: &EncryptionEngine, grant: &RepoKeyGrant) -> Result<String> {
    use base64::Engine as _;
    let sig = engine.sign_data(&grant.canonical())?;
    Ok(base64::engine::general_purpose::STANDARD.encode(sig))
}

/// Verify a base64 detached signature over a [`RepoKeyGrant`]'s canonical
/// against the granter's armored public cert.
///
/// **Fail-closed contract.** Returns `Ok(false)` for an EMPTY signature (an
/// unsigned grant is never valid — the pre-I-1 shape must not silently pass)
/// and for a signature that does not verify. Returns `Err` only when the cert
/// cannot be parsed or the base64 is malformed — callers must treat an `Err`
/// as a refusal too, never as "skip the check".
///
/// This proves AUTHORSHIP of the tuple only. The caller MUST separately
/// establish that `grant.granter_fingerprint` is the cert it verified against,
/// and that the granter is actually authorized to grant this repo.
pub fn verify_repo_key_grant(
    granter_cert_armored: &str,
    grant: &RepoKeyGrant,
    signature_b64: &str,
) -> Result<bool> {
    verify_signed_bytes(granter_cert_armored, &grant.canonical(), signature_b64)
}

/// The plaintext that gets encrypted to the recipient — the granted key plus
/// everything needed to verify who authored the grant.
///
/// Wire format is JSON (the payload is already opaque ciphertext to the relay,
/// so a self-describing format costs nothing and stays debuggable). The signed
/// bytes are the [`RepoKeyGrant`] canonical, NOT this JSON — so serde field
/// order, whitespace, or a future additive field cannot break signatures.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GrantBundle {
    /// Format discriminator. MUST equal [`GRANT_CANONICAL_VERSION`]; anything
    /// else is refused rather than guessed at.
    pub v: String,
    /// The repository's immutable id the grant was signed for. Inside the
    /// ciphertext, so the relay neither learns nor edits it, and covered by the
    /// signature. Required: a bundle without one is refused by
    /// [`GrantBundle::from_json`] (after its version check, so a retired v1
    /// bundle is refused as the wrong version). The importer records it as the
    /// repository's uid (and refuses a grant whose uid differs from one already
    /// recorded).
    #[serde(default)]
    pub repo_uid: String,
    /// The granted repo key: base64 of the serialized TSK.
    pub key_material_b64: String,
    /// The granter's identity fingerprint (whose cert must verify `grant_sig_b64`).
    pub granter_fingerprint: String,
    /// Issuance time, unix seconds.
    pub timestamp_unix: i64,
    /// Base64 detached signature over the [`RepoKeyGrant`] canonical — or, when
    /// `delegation` is present, over [`RepoKeyGrant::canonical_with_delegation`].
    pub grant_sig_b64: String,
    /// The owner-signed delegation authorizing a non-owner granter (KTD-6).
    /// Absent for an owner-signed grant, and then omitted from the JSON, so an
    /// owner's bundle is byte-identical to the pre-KTD-6 shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<GrantDelegation>,
}

impl GrantBundle {
    /// Reconstruct the signed tuple from this bundle plus the values the
    /// RECIPIENT supplies (`key_version` from the relayed grant envelope;
    /// `recipient_fingerprint`, its own identity). The repository is the
    /// bundle's own signed uid; whether that is the repository the caller meant
    /// is [`verify_grant_bundle`]'s check.
    pub fn to_grant(&self, key_version: i32, recipient_fingerprint: &str) -> RepoKeyGrant {
        RepoKeyGrant::new(
            self.repo_uid.clone(),
            key_version,
            recipient_fingerprint,
            &self.granter_fingerprint,
            self.key_material_b64.clone(),
            self.timestamp_unix,
        )
    }

    /// The delegation this bundle carries, if any. Its integrity is covered by
    /// the grant signature, so read it only after [`verify_grant_bundle`] says
    /// [`GrantVerifyOutcome::Valid`].
    pub fn delegation(&self) -> Option<&GrantDelegation> {
        self.delegation.as_ref()
    }

    /// The carried delegation as a `RepoDelegation` plus its owner signature,
    /// ready for `authorize_repo_grant(.., delegation.as_ref().map(|(d, s)| (d,
    /// s.as_str())), ..)`. `None` when the bundle carries no delegation.
    #[cfg(feature = "key-directory")]
    pub fn repo_delegation(&self) -> Option<(crate::key_directory::repo_owner::RepoDelegation, String)> {
        self.delegation.as_ref().map(|d| {
            (
                crate::key_directory::repo_owner::RepoDelegation::from_bundled(d),
                d.delegation_sig_b64.clone(),
            )
        })
    }

    /// Serialize for encryption to the recipient.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| CryptoError::Encryption(format!("grant bundle serialize failed: {e}")))
    }

    /// Parse a decrypted grant payload. STRICT: rejects a non-JSON payload (e.g.
    /// a pre-I-1 bare TSK) and a wrong/absent version tag, so an unsigned legacy
    /// grant can never alias-parse into a bundle and skip verification.
    pub fn from_json(bytes: &[u8]) -> Result<GrantBundle> {
        let bundle: GrantBundle = serde_json::from_slice(bytes).map_err(|e| {
            CryptoError::Decryption(format!(
                "grant payload is not a gc-grant bundle (a pre-I-1 unsigned grant looks like \
                 this — it must be re-issued, not imported): {e}"
            ))
        })?;
        if bundle.v != GRANT_CANONICAL_VERSION {
            return Err(CryptoError::Decryption(format!(
                "unsupported grant bundle version {:?} (expected {:?})",
                bundle.v, GRANT_CANONICAL_VERSION
            )));
        }
        if bundle.repo_uid.trim().is_empty() {
            return Err(CryptoError::Decryption(
                "grant bundle names no repo_uid; a gc-grant-v2 grant always binds one".to_string(),
            ));
        }
        Ok(bundle)
    }
}

/// Build a signed [`GrantBundle`] for the repository `repo_uid` — the
/// granter-side composition point. With a
/// `delegation` (KTD-6) the granter's signature covers it too (see
/// [`RepoKeyGrant::canonical_with_delegation`]).
///
/// `granter_engine` MUST hold the granting identity's secret key.
/// `key_material_b64` is base64 of the serialized TSK being granted. This does
/// not check that a delegation authorizes the granter; the recipient decides
/// that with `authorize_repo_grant`, and the owner's signer refuses a
/// non-conforming delegation before it exists.
#[allow(clippy::too_many_arguments)]
pub fn build_signed_repo_grant_bundle(
    granter_engine: &EncryptionEngine,
    repo_uid: &str,
    key_version: i32,
    recipient_fingerprint: &str,
    key_material_b64: &str,
    timestamp_unix: i64,
    delegation: Option<GrantDelegation>,
) -> Result<GrantBundle> {
    use base64::Engine as _;
    let granter_fingerprint = normalize_fingerprint(&granter_engine.fingerprint());
    let grant = RepoKeyGrant::new(
        repo_uid,
        key_version,
        recipient_fingerprint,
        &granter_fingerprint,
        key_material_b64,
        timestamp_unix,
    );
    let sig = granter_engine.sign_data(&grant.canonical_with_delegation(delegation.as_ref()))?;
    Ok(GrantBundle {
        v: GRANT_CANONICAL_VERSION.to_string(),
        repo_uid: repo_uid.to_string(),
        key_material_b64: key_material_b64.to_string(),
        granter_fingerprint,
        timestamp_unix,
        grant_sig_b64: base64::engine::general_purpose::STANDARD.encode(sig),
        delegation,
    })
}

/// [`build_signed_repo_grant_bundle`] with no delegation: an owner's grant of
/// the repository `repo_uid`.
pub fn build_signed_grant_bundle(
    granter_engine: &EncryptionEngine,
    repo_uid: &str,
    key_version: i32,
    recipient_fingerprint: &str,
    key_material_b64: &str,
    timestamp_unix: i64,
) -> Result<GrantBundle> {
    build_signed_repo_grant_bundle(
        granter_engine,
        repo_uid,
        key_version,
        recipient_fingerprint,
        key_material_b64,
        timestamp_unix,
        None,
    )
}

/// [`build_signed_repo_grant_bundle`] carrying `delegation` (KTD-6): a
/// delegate's grant of the repository `repo_uid`.
pub fn build_signed_delegated_grant_bundle(
    granter_engine: &EncryptionEngine,
    repo_uid: &str,
    key_version: i32,
    recipient_fingerprint: &str,
    key_material_b64: &str,
    timestamp_unix: i64,
    delegation: GrantDelegation,
) -> Result<GrantBundle> {
    build_signed_repo_grant_bundle(
        granter_engine,
        repo_uid,
        key_version,
        recipient_fingerprint,
        key_material_b64,
        timestamp_unix,
        Some(delegation),
    )
}

/// Outcome of the recipient-side grant check. Every non-`Valid` variant means
/// REFUSE THE IMPORT; `alarm` marks the ones that are cryptographic evidence of
/// an attack rather than a benign/transient condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantVerifyOutcome {
    /// Signature verified as the granter's over exactly this tuple.
    Valid,
    /// The bundle's `granter_fingerprint` is not the cert we verified against —
    /// someone is presenting another party's key as the granter's.
    GranterFingerprintMismatch { claimed: String, served: String },
    /// A well-formed signature that does not verify, or an absent one. This is
    /// the forged/unsigned grant case.
    SignatureInvalid,
    /// The signature or cert could not even be processed.
    Malformed(String),
}

impl GrantVerifyOutcome {
    /// May the caller import this grant?
    pub fn allow(&self) -> bool {
        matches!(self, GrantVerifyOutcome::Valid)
    }

    /// Is this refusal cryptographic evidence of tampering (log loudly), rather
    /// than a benign shape problem?
    pub fn alarm(&self) -> bool {
        matches!(
            self,
            GrantVerifyOutcome::SignatureInvalid
                | GrantVerifyOutcome::GranterFingerprintMismatch { .. }
        )
    }

    /// Human-readable reason for logs.
    pub fn reason(&self) -> String {
        match self {
            GrantVerifyOutcome::Valid => "grant signature verified".to_string(),
            GrantVerifyOutcome::GranterFingerprintMismatch { claimed, served } => format!(
                "grant claims granter fingerprint {claimed} but the served granter cert is \
                 {served}"
            ),
            GrantVerifyOutcome::SignatureInvalid => {
                "grant origin signature is absent or does not verify under the granter's cert"
                    .to_string()
            }
            GrantVerifyOutcome::Malformed(m) => format!("grant signature unprocessable: {m}"),
        }
    }
}

/// RECIPIENT-SIDE gate: verify a decrypted [`GrantBundle`] was authored by the
/// granter whose cert is `granter_cert_armored`, for exactly this repo, version
/// and recipient.
///
/// `repo_uid` is the repository the caller means, by its immutable id, which
/// survives a rename. A bundle signed for any other uid is a grant re-aimed at
/// another repository and is refused as [`GrantVerifyOutcome::SignatureInvalid`],
/// as a v1 re-aim was. A name is never a uid, so a caller that still passes
/// one verifies nothing.
///
/// Fail-closed: anything other than [`GrantVerifyOutcome::Valid`] means do not
/// import. Note this proves AUTHORSHIP, not AUTHORIZATION — the caller must
/// still establish that the served granter cert is the real account's key (via the key directory)
/// and that the granter may grant this repo.
pub fn verify_grant_bundle(
    bundle: &GrantBundle,
    granter_cert_armored: &str,
    granter_served_fingerprint: &str,
    repo_uid: &str,
    key_version: i32,
    recipient_fingerprint: &str,
) -> GrantVerifyOutcome {
    let claimed = normalize_fingerprint(&bundle.granter_fingerprint);
    let served = normalize_fingerprint(granter_served_fingerprint);
    if claimed != served {
        return GrantVerifyOutcome::GranterFingerprintMismatch { claimed, served };
    }

    if repo_uid.is_empty() || bundle.repo_uid != repo_uid {
        return GrantVerifyOutcome::SignatureInvalid;
    }
    let grant = bundle.to_grant(key_version, recipient_fingerprint);
    let verified = match &bundle.delegation {
        None => verify_repo_key_grant(granter_cert_armored, &grant, &bundle.grant_sig_b64),
        Some(del) => verify_signed_bytes(
            granter_cert_armored,
            &grant.canonical_with_delegation(Some(del)),
            &bundle.grant_sig_b64,
        ),
    };
    match verified {
        Ok(true) => GrantVerifyOutcome::Valid,
        Ok(false) => GrantVerifyOutcome::SignatureInvalid,
        Err(e) => GrantVerifyOutcome::Malformed(e.to_string()),
    }
}

/// Shared fail-closed detached-signature check: empty is `Ok(false)`, bad
/// base64 is `Err`.
fn verify_signed_bytes(cert_armored: &str, signed: &[u8], signature_b64: &str) -> Result<bool> {
    use base64::Engine as _;
    if signature_b64.is_empty() {
        return Ok(false);
    }
    let sig = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|e| CryptoError::OpenPgp(format!("grant sig is not valid base64: {e}")))?;
    verify_detached(cert_armored, signed, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    fn engine_and_cert(email: &str) -> (EncryptionEngine, String) {
        let identity = Identity::generate(email).unwrap();
        let armored = identity.export_public_key().unwrap();
        let engine = EncryptionEngine::new(identity).unwrap();
        (engine, armored)
    }

    fn grant() -> RepoKeyGrant {
        RepoKeyGrant::new(
            "alice/secret-repo",
            3,
            "BBBB2222CCCC3333DDDD4444EEEE5555FFFF6666",
            "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
            "d3JhcHBlZC1yZXBvLWtleS1ieXRlcw==",
            1_750_000_000,
        )
    }

    // ---- canonical shape ----

    /// Freeze the exact signed bytes. A silent codec change would split granter
    /// and recipient (every grant would fail to verify) — fail loudly here.
    #[test]
    fn golden_canonical_is_frozen() {
        let g = RepoKeyGrant::new("u", 1, "AB", "CD", "V0s=", 1_750_000_000);
        let expected =
            b"11:gc-grant-v2\n1:u\n1:1\n2:AB\n2:CD\n4:V0s=\n10:1750000000\n".to_vec();
        assert_eq!(g.canonical(), expected);
    }

    /// Fingerprint rendering must not change the signed bytes: spaced/lowercase
    /// and unspaced/uppercase forms of the same fingerprint canonicalize alike.
    #[test]
    fn fingerprint_rendering_does_not_change_the_canonical() {
        let unspaced = RepoKeyGrant::new("r", 1, "aabb ccdd", "1122 3344", "V0s=", 7);
        let spaced = RepoKeyGrant::new("r", 1, "AABBCCDD", "11223344", "V0s=", 7);
        assert_eq!(unspaced.canonical(), spaced.canonical());

        // ...even when the struct is built by literal rather than `new`.
        let literal = RepoKeyGrant {
            repo_uid: "r".to_string(),
            key_version: 1,
            recipient_fingerprint: "aabb ccdd".to_string(),
            granter_fingerprint: "1122 3344".to_string(),
            key_material_b64: "V0s=".to_string(),
            timestamp_unix: 7,
        };
        assert_eq!(literal.canonical(), spaced.canonical());
    }

    /// Length prefixes make the composition injection-safe: content cannot be
    /// shifted across a field boundary to produce the same signed bytes.
    #[test]
    fn field_boundaries_cannot_be_forged() {
        let a = RepoKeyGrant::new("a", 1, "AB", "CD", "V0s=", 7);
        let b = RepoKeyGrant::new("a\n1:1", 1, "AB", "CD", "V0s=", 7);
        assert_ne!(a.canonical(), b.canonical());
    }

    /// Every field is actually bound — changing any one changes the bytes.
    #[test]
    fn every_field_is_bound_into_the_canonical() {
        let base = grant().canonical();
        let variants = [
            RepoKeyGrant { repo_uid: "mallory/other".to_string(), ..grant() },
            RepoKeyGrant { key_version: 4, ..grant() },
            RepoKeyGrant { recipient_fingerprint: "0".repeat(40), ..grant() },
            RepoKeyGrant { granter_fingerprint: "0".repeat(40), ..grant() },
            RepoKeyGrant { key_material_b64: "b3RoZXIta2V5".to_string(), ..grant() },
            RepoKeyGrant { timestamp_unix: 1_750_000_001, ..grant() },
        ];
        for v in &variants {
            assert_ne!(v.canonical(), base, "changing {v:?} must change the signed bytes");
        }
    }

    // ---- sign / verify ----

    /// A GENUINE grant verifies against the granter's cert.
    #[test]
    fn genuine_grant_verifies() {
        let (granter, granter_cert) = engine_and_cert("owner@example.com");
        let g = grant();
        let sig = sign_repo_key_grant(&granter, &g).unwrap();
        assert!(verify_repo_key_grant(&granter_cert, &g, &sig).unwrap());
    }

    /// FAIL-CLOSED — an absent signature is never valid. This is the pre-I-1
    /// shape (a grant with no origin signature); it must not pass.
    #[test]
    fn absent_signature_is_rejected() {
        let (_granter, granter_cert) = engine_and_cert("owner@example.com");
        assert!(!verify_repo_key_grant(&granter_cert, &grant(), "").unwrap());
    }

    /// FORGED — a signature by a DIFFERENT key does not verify as the granter's.
    /// This is the attack: the Cloud (or anyone with write access) substitutes
    /// its own key and signs the grant itself.
    #[test]
    fn signature_from_a_foreign_key_is_rejected() {
        let (attacker, _attacker_cert) = engine_and_cert("mallory@evil.test");
        let (_granter, granter_cert) = engine_and_cert("owner@example.com");
        let g = grant();

        let forged = sign_repo_key_grant(&attacker, &g).unwrap();
        assert!(!verify_repo_key_grant(&granter_cert, &g, &forged).unwrap());
    }

    /// TAMPERED — the key-substitution attack I-1 exists to stop. A genuine
    /// signature over the real grant must NOT verify once the granted key is
    /// swapped for the attacker's.
    #[test]
    fn swapped_key_material_invalidates_the_signature() {
        let (granter, granter_cert) = engine_and_cert("owner@example.com");
        let g = grant();
        let sig = sign_repo_key_grant(&granter, &g).unwrap();

        let swapped = RepoKeyGrant {
            key_material_b64: "YXR0YWNrZXIta25vd24ta2V5".to_string(),
            ..g.clone()
        };
        assert!(!verify_repo_key_grant(&granter_cert, &swapped, &sig).unwrap());

        // ...and the untampered grant still verifies (the check isn't just
        // always-false).
        assert!(verify_repo_key_grant(&granter_cert, &g, &sig).unwrap());
    }

    /// REPLAY — a grant genuinely issued to Alice must not verify when relayed
    /// to Bob, or re-aimed at another repo / key version.
    #[test]
    fn grant_cannot_be_replayed_to_another_recipient_repo_or_version() {
        let (granter, granter_cert) = engine_and_cert("owner@example.com");
        let g = grant();
        let sig = sign_repo_key_grant(&granter, &g).unwrap();

        for replay in [
            RepoKeyGrant { recipient_fingerprint: "9".repeat(40), ..g.clone() },
            RepoKeyGrant { repo_uid: "alice/other-repo".to_string(), ..g.clone() },
            RepoKeyGrant { key_version: 4, ..g.clone() },
        ] {
            assert!(
                !verify_repo_key_grant(&granter_cert, &replay, &sig).unwrap(),
                "replayed grant must not verify: {replay:?}"
            );
        }
    }

    /// A malformed signature is an ERROR (not a silent pass), and a non-cert is
    /// an error too — callers must refuse on `Err`, never skip the check.
    #[test]
    fn malformed_inputs_error_rather_than_pass() {
        let (_g, granter_cert) = engine_and_cert("owner@example.com");
        assert!(verify_repo_key_grant(&granter_cert, &grant(), "!!not base64!!").is_err());
        assert!(verify_repo_key_grant("not a cert", &grant(), "V0s=").is_err());
    }

    // ---- bundle: the end-to-end recipient gate ----

    const REPO: &str = "alice/secret-repo";
    const VERSION: i32 = 3;
    const KEY_B64: &str = "dHNrLWJ5dGVzLWZvci10aGUtcmVwby1rZXk=";

    /// HAPPY PATH — a genuinely signed bundle, round-tripped through the JSON
    /// wire format, verifies for the intended recipient.
    #[test]
    fn genuine_bundle_round_trips_and_verifies() {
        let (granter, granter_cert) = engine_and_cert("owner@example.com");
        let (recipient, _rc) = engine_and_cert("collab@example.com");
        let rfp = recipient.fingerprint();

        let bundle =
            build_signed_grant_bundle(&granter, REPO, VERSION, &rfp, KEY_B64, 1_750_000_000)
                .unwrap();

        // Through the wire: json -> bytes -> json (what encrypt/decrypt does).
        let wire = bundle.to_json().unwrap();
        let got = GrantBundle::from_json(&wire).unwrap();
        assert_eq!(got.key_material_b64, KEY_B64);

        let outcome =
            verify_grant_bundle(&got, &granter_cert, &granter.fingerprint(), REPO, VERSION, &rfp);
        assert_eq!(outcome, GrantVerifyOutcome::Valid);
        assert!(outcome.allow());
    }

    /// FAIL-CLOSED — a pre-I-1 payload (a bare TSK, not bundle JSON) must be
    /// REFUSED, never imported unverified. This is the regression guard for the
    /// whole point of I-1: unsigned grants must stop working.
    #[test]
    fn legacy_unsigned_payload_is_refused() {
        let legacy_tsk = b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nnot json\n";
        let err = GrantBundle::from_json(legacy_tsk).unwrap_err();
        assert!(format!("{err}").contains("not a gc-grant bundle"));

        // A wrong version tag is refused too (never guessed at) — the retired
        // v1 tag included.
        let wrong = serde_json::json!({
            "v": "gc-grant-v1",
            "key_material_b64": KEY_B64,
            "granter_fingerprint": "AB",
            "timestamp_unix": 1,
            "grant_sig_b64": "V0s=",
        });
        let err = GrantBundle::from_json(&serde_json::to_vec(&wrong).unwrap()).unwrap_err();
        assert!(format!("{err}").contains("unsupported grant bundle version"));
    }

    /// THE ATTACK — the Cloud substitutes its own repo key and signs the grant
    /// with its own identity, presenting itself as the granter. The recipient
    /// verifies against the REAL granter's cert, so this is refused + alarmed.
    #[test]
    fn attacker_signed_grant_is_refused_and_alarms() {
        let (attacker, attacker_cert) = engine_and_cert("mallory@evil.test");
        let (granter, granter_cert) = engine_and_cert("owner@example.com");
        let (recipient, _rc) = engine_and_cert("collab@example.com");
        let rfp = recipient.fingerprint();

        // Attacker mints a fully-valid-looking bundle around THEIR key.
        let evil = build_signed_grant_bundle(
            &attacker,
            REPO,
            VERSION,
            &rfp,
            "YXR0YWNrZXIta25vd24ta2V5",
            1_750_000_000,
        )
        .unwrap();

        // It verifies under the attacker's OWN cert (the forgery is internally
        // consistent — which is exactly why the served cert must be the real
        // granter's, i.e. verified against the key directory).
        let self_consistent = verify_grant_bundle(
            &evil, &attacker_cert, &attacker.fingerprint(), REPO, VERSION, &rfp,
        );
        assert_eq!(self_consistent, GrantVerifyOutcome::Valid);

        // ...but against the REAL granter it fails on the fingerprint bind,
        // before the signature is even consulted.
        let outcome =
            verify_grant_bundle(&evil, &granter_cert, &granter.fingerprint(), REPO, VERSION, &rfp);
        assert!(!outcome.allow());
        assert!(outcome.alarm(), "a substituted granter must ALARM, not pass quietly");
        assert!(matches!(outcome, GrantVerifyOutcome::GranterFingerprintMismatch { .. }));
    }

    /// TAMPER — the Cloud keeps the granter's real signature but swaps the key
    /// material inside the bundle. The signature no longer covers it → refused.
    #[test]
    fn bundle_with_swapped_key_material_is_refused_and_alarms() {
        let (granter, granter_cert) = engine_and_cert("owner@example.com");
        let (recipient, _rc) = engine_and_cert("collab@example.com");
        let rfp = recipient.fingerprint();

        let mut bundle =
            build_signed_grant_bundle(&granter, REPO, VERSION, &rfp, KEY_B64, 1_750_000_000)
                .unwrap();
        bundle.key_material_b64 = "YXR0YWNrZXIta25vd24ta2V5".to_string();

        let outcome = verify_grant_bundle(
            &bundle, &granter_cert, &granter.fingerprint(), REPO, VERSION, &rfp,
        );
        assert_eq!(outcome, GrantVerifyOutcome::SignatureInvalid);
        assert!(!outcome.allow());
        assert!(outcome.alarm());
    }

    /// RE-AIM — a grant genuinely issued to Alice, relayed to Bob (or re-labeled
    /// as another repo/version), must not verify. The verifier supplies these
    /// three values itself, so rewriting the bundle cannot help.
    #[test]
    fn bundle_cannot_be_re_aimed_at_another_recipient_repo_or_version() {
        let (granter, granter_cert) = engine_and_cert("owner@example.com");
        let (alice, _a) = engine_and_cert("alice@example.com");
        let (bob, _b) = engine_and_cert("bob@example.com");
        let gfp = granter.fingerprint();

        let bundle = build_signed_grant_bundle(
            &granter, REPO, VERSION, &alice.fingerprint(), KEY_B64, 1_750_000_000,
        )
        .unwrap();

        // Relayed to Bob.
        assert_eq!(
            verify_grant_bundle(&bundle, &granter_cert, &gfp, REPO, VERSION, &bob.fingerprint()),
            GrantVerifyOutcome::SignatureInvalid
        );
        // Re-labeled repo.
        assert_eq!(
            verify_grant_bundle(
                &bundle, &granter_cert, &gfp, "alice/other", VERSION, &alice.fingerprint()
            ),
            GrantVerifyOutcome::SignatureInvalid
        );
        // Re-labeled version.
        assert_eq!(
            verify_grant_bundle(
                &bundle, &granter_cert, &gfp, REPO, VERSION + 1, &alice.fingerprint()
            ),
            GrantVerifyOutcome::SignatureInvalid
        );
        // Sanity: the untouched aim still verifies.
        assert_eq!(
            verify_grant_bundle(
                &bundle, &granter_cert, &gfp, REPO, VERSION, &alice.fingerprint()
            ),
            GrantVerifyOutcome::Valid
        );
    }

    /// An empty signature in an otherwise well-formed bundle is refused (the
    /// "someone stripped the signature" case).
    #[test]
    fn bundle_with_stripped_signature_is_refused() {
        let (granter, granter_cert) = engine_and_cert("owner@example.com");
        let (recipient, _rc) = engine_and_cert("collab@example.com");
        let rfp = recipient.fingerprint();

        let mut bundle =
            build_signed_grant_bundle(&granter, REPO, VERSION, &rfp, KEY_B64, 1_750_000_000)
                .unwrap();
        bundle.grant_sig_b64 = String::new();

        let outcome = verify_grant_bundle(
            &bundle, &granter_cert, &granter.fingerprint(), REPO, VERSION, &rfp,
        );
        assert_eq!(outcome, GrantVerifyOutcome::SignatureInvalid);
        assert!(!outcome.allow());
    }
}
