mod audit;
mod normalize;
mod plan;
mod receipt;
mod verify;

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use chrono::{SecondsFormat, Utc};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
};

use crate::{
    audit::verify_chain,
    plan::{ApplyMode, KeySource, Plan as KKPlan, PromotionReceiptPayload, TrustRoot},
    receipt::{
        build_receipt_from_signature, build_signed_receipt, build_trust_root_from_public_key,
        build_trust_root_from_signing_key, read_json_file, sha256_hex, write_receipt_template,
        write_trust_root_template, SENTINEL_ONLY_SCOPE,
    },
    verify::{verify_apply_dir, VerifyOptions},
};

#[derive(Parser)]
#[command(name = "kernelkit", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,

    /// Base output directory for artifacts (default: /vault/ai_data/logs/kernelkit/applies)
    #[arg(long, default_value = "/vault/ai_data/logs/kernelkit/applies")]
    out_dir: String,
}

#[derive(Subcommand)]
enum Command {
    Profile {
        #[command(subcommand)]
        cmd: ProfileCmd,
    },
}

#[derive(Subcommand)]
enum ProfileCmd {
    Apply {
        plan: String,
        #[arg(long)]
        propose_only: bool,
        #[arg(long)]
        apply: bool,
    },
    Verify {
        apply_dir: String,
        #[arg(long)]
        receipt: Option<String>,
        #[arg(long)]
        trust_root: Option<String>,
        #[arg(long)]
        audit: Option<String>,
    },
    SignReceipt {
        apply_dir: String,
        #[arg(long)]
        signing_key_b64: Option<String>,
        #[arg(long)]
        signing_key_file: Option<String>,
        #[arg(long)]
        kms_sign_cmd: Option<String>,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        out: Option<String>,
        #[arg(long)]
        trust_root_out: Option<String>,
        #[arg(long)]
        public_key_b64: Option<String>,
        #[arg(long)]
        key_source: Option<String>,
        #[arg(long, default_value_t = 1)]
        rotation_epoch: u32,
        #[arg(long)]
        not_before: Option<String>,
        #[arg(long)]
        not_after: Option<String>,
        #[arg(long)]
        issued_at: Option<String>,
    },
    AttestBuild {
        #[arg(long, default_value = ".")]
        workspace: String,
        #[arg(long, default_value = "artifacts/attestations")]
        out_dir: String,
        #[arg(long)]
        signing_key_b64: Option<String>,
        #[arg(long)]
        signing_key_file: Option<String>,
        #[arg(long)]
        kms_sign_cmd: Option<String>,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        public_key_b64: Option<String>,
        #[arg(long)]
        key_source: Option<String>,
    },
    VerifyAttestation {
        file: String,
    },
    RotateTrustRoot {
        trust_root: String,
        #[arg(long)]
        new_key_id: String,
        #[arg(long)]
        new_public_key_b64: String,
        #[arg(long)]
        key_source: Option<String>,
        #[arg(long, default_value_t = 1)]
        rotation_epoch: u32,
        #[arg(long)]
        not_before: Option<String>,
        #[arg(long)]
        not_after: Option<String>,
        #[arg(long)]
        revoke_key_id: Vec<String>,
        #[arg(long)]
        out: Option<String>,
    },
    AuditVerify {
        audit_chain: String,
    },
    Rollback {
        apply_dir: String,
    },
    List,
    Diff {
        plan: String,
        #[arg(long, default_value = "current")]
        against: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Profile { cmd } => run_profile(cmd, PathBuf::from(cli.out_dir)),
    }
}

fn run_profile(cmd: ProfileCmd, out_base: PathBuf) -> Result<()> {
    match cmd {
        ProfileCmd::List => {
            println!("profiles: silicon_constrained_nomad, sovereign_intelligence_architect, immutable_operator");
            Ok(())
        }
        ProfileCmd::Diff { plan, against: _ } => {
            let _ = load_plan(&plan)?;
            println!(
                "diff: stub (v0.1). would inspect current sysctl/cmdline/dropins and compare."
            );
            Ok(())
        }
        ProfileCmd::Verify {
            apply_dir,
            receipt,
            trust_root,
            audit,
        } => {
            let dir = PathBuf::from(apply_dir);
            let outcome = verify_apply_dir(
                &dir,
                &VerifyOptions {
                    receipt_path: receipt.map(PathBuf::from),
                    trust_root_path: trust_root.map(PathBuf::from),
                    audit_path: audit.map(PathBuf::from),
                },
            )?;
            println!(
                "KERNELKIT_VERIFY_OK dir={} plan_id={} key_id={} scope={}",
                dir.display(),
                outcome.plan_id,
                outcome.key_id,
                SENTINEL_ONLY_SCOPE
            );
            Ok(())
        }
        ProfileCmd::SignReceipt {
            apply_dir,
            signing_key_b64,
            signing_key_file,
            kms_sign_cmd,
            key_id,
            out,
            trust_root_out,
            public_key_b64,
            key_source,
            rotation_epoch,
            not_before,
            not_after,
            issued_at,
        } => {
            let dir = PathBuf::from(apply_dir);
            let resolved_yaml = fs::read(dir.join("plan.resolved.yaml")).with_context(|| {
                format!(
                    "sign-receipt: missing plan.resolved.yaml in {}",
                    dir.display()
                )
            })?;
            let plan: KKPlan = serde_yaml::from_slice(&resolved_yaml)
                .context("sign-receipt: parse plan.resolved.yaml")?;
            let resolved_sha = sha256_hex(&resolved_yaml);
            let preflight = fs::read(dir.join("preflight.json")).with_context(|| {
                format!("sign-receipt: missing preflight.json in {}", dir.display())
            })?;
            let preflight_sha = sha256_hex(&preflight);

            let payload = PromotionReceiptPayload {
                plan_id: plan.plan_id,
                resolved_sha256: resolved_sha,
                preflight_sha256: preflight_sha,
                issued_at: issued_at
                    .unwrap_or_else(|| Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)),
            };
            let provider =
                resolve_signing_provider(signing_key_b64, signing_key_file, kms_sign_cmd)?;
            let source = parse_key_source(key_source.as_deref().unwrap_or("kms"))?;
            let receipt = match &provider {
                SigningProvider::RawB64(secret) => {
                    build_signed_receipt(payload, key_id.clone(), secret)?
                }
                SigningProvider::File(secret) => {
                    build_signed_receipt(payload, key_id.clone(), secret)?
                }
                SigningProvider::KmsCommand(cmd) => {
                    let payload_bytes = crate::receipt::canonical_payload_bytes(&payload)?;
                    let payload_b64 =
                        base64::engine::general_purpose::STANDARD.encode(payload_bytes);
                    let signature_b64 = run_kms_sign_command(cmd, &key_id, &payload_b64)?;
                    build_receipt_from_signature(payload, key_id.clone(), signature_b64)?
                }
            };
            let out_path = out
                .map(PathBuf::from)
                .unwrap_or_else(|| dir.join("promotion.receipt.json"));
            fs::write(
                &out_path,
                format!("{}\n", serde_json::to_string_pretty(&receipt)?),
            )
            .with_context(|| format!("sign-receipt: write {}", out_path.display()))?;
            let trust_root = match &provider {
                SigningProvider::RawB64(secret) | SigningProvider::File(secret) => {
                    build_trust_root_from_signing_key(secret, key_id)?
                }
                SigningProvider::KmsCommand(_) => {
                    let pub_key = public_key_b64.ok_or_else(|| {
                        anyhow!(
                            "sign-receipt: --public-key-b64 is required when using --kms-sign-cmd"
                        )
                    })?;
                    build_trust_root_from_public_key(
                        key_id,
                        pub_key,
                        source,
                        rotation_epoch,
                        not_before,
                        not_after,
                    )?
                }
            };
            let trust_root_path = trust_root_out
                .map(PathBuf::from)
                .unwrap_or_else(|| dir.join("trust-root.json"));
            fs::write(
                &trust_root_path,
                format!("{}\n", serde_json::to_string_pretty(&trust_root)?),
            )
            .with_context(|| format!("sign-receipt: write {}", trust_root_path.display()))?;
            println!(
                "KERNELKIT_SIGN_RECEIPT_OK dir={} out={} trust_root={}",
                dir.display(),
                out_path.display(),
                trust_root_path.display()
            );
            Ok(())
        }
        ProfileCmd::AttestBuild {
            workspace,
            out_dir,
            signing_key_b64,
            signing_key_file,
            kms_sign_cmd,
            key_id,
            public_key_b64,
            key_source,
        } => {
            let provider =
                resolve_signing_provider(signing_key_b64, signing_key_file, kms_sign_cmd)?;
            let workspace_path = PathBuf::from(&workspace);
            let out_dir_path = PathBuf::from(&out_dir);
            generate_build_attestation(
                &workspace_path,
                &out_dir_path,
                &provider,
                &key_id,
                public_key_b64,
                parse_key_source(key_source.as_deref().unwrap_or("kms"))?,
            )?;
            println!("KERNELKIT_ATTEST_BUILD_OK out_dir={}", out_dir);
            Ok(())
        }
        ProfileCmd::VerifyAttestation { file } => {
            verify_build_attestation(&PathBuf::from(file))?;
            println!("KERNELKIT_VERIFY_ATTESTATION_OK");
            Ok(())
        }
        ProfileCmd::RotateTrustRoot {
            trust_root,
            new_key_id,
            new_public_key_b64,
            key_source,
            rotation_epoch,
            not_before,
            not_after,
            revoke_key_id,
            out,
        } => {
            let trust_root_path = PathBuf::from(trust_root);
            let mut root: TrustRoot =
                read_json_file(&trust_root_path, "trust root").with_context(|| {
                    format!("rotate-trust-root: read {}", trust_root_path.display())
                })?;
            for key in &mut root.keys {
                if key.status == crate::plan::TrustRootKeyStatus::Active {
                    key.status = crate::plan::TrustRootKeyStatus::Retired;
                }
                if revoke_key_id.iter().any(|id| id == &key.key_id) {
                    key.status = crate::plan::TrustRootKeyStatus::Revoked;
                }
            }
            if root.keys.iter().any(|k| k.key_id == new_key_id) {
                return Err(anyhow!(
                    "rotate-trust-root: key_id already exists: {}",
                    new_key_id
                ));
            }
            root.keys.push(crate::plan::TrustRootKey {
                key_id: new_key_id,
                public_key_b64: new_public_key_b64,
                source: parse_key_source(key_source.as_deref().unwrap_or("kms"))?,
                rotation_epoch,
                not_before,
                not_after,
                status: crate::plan::TrustRootKeyStatus::Active,
            });
            crate::receipt::validate_trust_root_contract(&root)?;
            let out_path = out.map(PathBuf::from).unwrap_or(trust_root_path);
            fs::write(
                &out_path,
                format!("{}\n", serde_json::to_string_pretty(&root)?),
            )
            .with_context(|| format!("rotate-trust-root: write {}", out_path.display()))?;
            println!("KERNELKIT_TRUST_ROOT_ROTATE_OK out={}", out_path.display());
            Ok(())
        }
        ProfileCmd::AuditVerify { audit_chain } => {
            let p = PathBuf::from(audit_chain);
            verify_chain(&p)?;
            println!("KERNELKIT_AUDIT_VERIFY_OK file={}", p.display());
            Ok(())
        }
        ProfileCmd::Rollback { apply_dir } => {
            let dir = PathBuf::from(apply_dir);
            let rb = dir.join("rollback.sh");
            if !rb.exists() {
                return Err(anyhow!(
                    "rollback: missing rollback.sh in {}",
                    dir.display()
                ));
            }
            println!(
                "KERNELKIT_ROLLBACK_READY dir={} cmd='sudo bash {}'",
                dir.display(),
                rb.display()
            );
            Ok(())
        }
        ProfileCmd::Apply {
            plan,
            propose_only,
            apply,
        } => {
            if propose_only && apply {
                return Err(anyhow!("choose only one: --propose-only or --apply"));
            }
            let p = load_plan(&plan)?;
            let resolved = normalize::normalize_plan(p);

            enforce_policy(&resolved, apply)?;

            let ts = Utc::now().format("%Y%m%d-%H%M%S").to_string();
            let out_dir = out_base.join(ts);
            fs::create_dir_all(&out_dir)
                .with_context(|| format!("create {}", out_dir.display()))?;

            let resolved_yaml = serde_yaml::to_string(&resolved)?;
            write_text(out_dir.join("plan.resolved.yaml"), &resolved_yaml)?;

            let hash = sha256_hex(resolved_yaml.as_bytes());
            write_text(out_dir.join("resolved.sha256"), &format!("{hash}\n"))?;

            let preflight = preflight_json(&resolved)?;
            write_text(
                out_dir.join("preflight.json"),
                &serde_json::to_string_pretty(&preflight)?,
            )?;
            let preflight_serialized = serde_json::to_string_pretty(&preflight)?;
            let preflight_hash = sha256_hex(preflight_serialized.as_bytes());

            let before_dir = out_dir.join("before");
            fs::create_dir_all(&before_dir)?;
            snapshot_paths(&resolved, &before_dir)?;

            let apply_sh = render_apply_sh(&resolved)?;
            write_text(out_dir.join("apply.sh"), &apply_sh)?;
            make_executable(out_dir.join("apply.sh"))?;

            let rollback_sh = render_rollback_sh(&resolved)?;
            write_text(out_dir.join("rollback.sh"), &rollback_sh)?;
            make_executable(out_dir.join("rollback.sh"))?;

            let after_dir = out_dir.join("after");
            fs::create_dir_all(&after_dir)?;
            write_text(after_dir.join("verify.json"), "{}\n")?;

            let payload = PromotionReceiptPayload {
                plan_id: resolved.plan_id.clone(),
                resolved_sha256: hash,
                preflight_sha256: preflight_hash,
                issued_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            };
            write_receipt_template(&out_dir.join("promotion.receipt.template.json"), &payload)?;
            if !out_dir.join("trust-root.json").exists() {
                write_trust_root_template(&out_dir.join("trust-root.template.json"))?;
            }

            if apply {
                return Err(anyhow!(
                    "apply: not implemented in v0.1. Use --propose-only. Artifacts at {}",
                    out_dir.display()
                ));
            }

            println!(
                "KERNELKIT_APPLY_OK plan_id={} dir={}",
                resolved.plan_id,
                out_dir.display()
            );
            Ok(())
        }
    }
}

enum SigningProvider {
    RawB64(String),
    File(String),
    KmsCommand(String),
}

fn resolve_signing_provider(
    signing_key_b64: Option<String>,
    signing_key_file: Option<String>,
    kms_sign_cmd: Option<String>,
) -> Result<SigningProvider> {
    let count = signing_key_b64.is_some() as u8
        + signing_key_file.is_some() as u8
        + kms_sign_cmd.is_some() as u8;
    if count != 1 {
        return Err(anyhow!(
            "sign-receipt: exactly one of --signing-key-b64, --signing-key-file, --kms-sign-cmd must be set"
        ));
    }
    if let Some(secret) = signing_key_b64 {
        return Ok(SigningProvider::RawB64(secret));
    }
    if let Some(path) = signing_key_file {
        let key = load_signing_key_file(&path)?;
        return Ok(SigningProvider::File(key));
    }
    Ok(SigningProvider::KmsCommand(
        kms_sign_cmd.expect("kms command present"),
    ))
}

fn load_signing_key_file(path: &str) -> Result<String> {
    let meta = fs::metadata(path).with_context(|| format!("signing key file metadata {}", path))?;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(anyhow!(
            "signing key file must not be group/world accessible: {} mode={:o}",
            path,
            mode & 0o777
        ));
    }
    let secret = fs::read_to_string(path)
        .with_context(|| format!("read signing key file {}", path))?
        .trim()
        .to_string();
    if secret.is_empty() {
        return Err(anyhow!("signing key file is empty: {}", path));
    }
    Ok(secret)
}

fn run_kms_sign_command(cmd: &str, key_id: &str, payload_b64: &str) -> Result<String> {
    let output = ProcessCommand::new(cmd)
        .arg(key_id)
        .arg(payload_b64)
        .output()
        .with_context(|| format!("run kms sign command: {}", cmd))?;
    if !output.status.success() {
        return Err(anyhow!(
            "kms sign command failed (status={}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let signature = String::from_utf8(output.stdout)
        .context("kms sign command output must be utf-8")?
        .trim()
        .to_string();
    if signature.is_empty() {
        return Err(anyhow!("kms sign command returned empty signature"));
    }
    Ok(signature)
}

fn parse_key_source(source: &str) -> Result<KeySource> {
    match source.to_ascii_lowercase().as_str() {
        "local" => Ok(KeySource::Local),
        "kms" => Ok(KeySource::Kms),
        "hsm" => Ok(KeySource::Hsm),
        other => Err(anyhow!(
            "unsupported key source '{}'; expected one of local|kms|hsm",
            other
        )),
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct BuildProvenancePayload {
    version: String,
    scope: String,
    generated_at: String,
    git_head: String,
    rustc: String,
    cargo: String,
    cargo_lock_sha256: String,
    sbom_sha256: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct BuildAttestation {
    statement_type: String,
    signature_algorithm: String,
    key_id: String,
    key_source: String,
    payload: BuildProvenancePayload,
    signature_b64: String,
    public_key_b64: String,
}

fn generate_build_attestation(
    workspace: &Path,
    out_dir: &Path,
    provider: &SigningProvider,
    key_id: &str,
    public_key_b64_override: Option<String>,
    key_source: KeySource,
) -> Result<()> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("create attestation dir {}", out_dir.display()))?;

    let cargo_lock = fs::read(workspace.join("Cargo.lock"))
        .with_context(|| format!("read {}", workspace.join("Cargo.lock").display()))?;
    let cargo_lock_sha256 = sha256_hex(&cargo_lock);

    let sbom_bytes = ProcessCommand::new("cargo")
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--manifest-path")
        .arg(workspace.join("Cargo.toml"))
        .output()
        .context("run cargo metadata for sbom")?;
    if !sbom_bytes.status.success() {
        return Err(anyhow!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&sbom_bytes.stderr)
        ));
    }
    fs::write(out_dir.join("sbom.cargo-metadata.json"), &sbom_bytes.stdout).with_context(|| {
        format!(
            "write {}",
            out_dir.join("sbom.cargo-metadata.json").display()
        )
    })?;
    let sbom_sha256 = sha256_hex(&sbom_bytes.stdout);

    let git_head = ProcessCommand::new("git")
        .arg("-C")
        .arg(workspace)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .context("get git head")?;
    let git_head = if git_head.status.success() {
        String::from_utf8(git_head.stdout)
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string()
    } else {
        "unknown".to_string()
    };

    let rustc = String::from_utf8(
        ProcessCommand::new("rustc")
            .arg("--version")
            .output()
            .context("run rustc --version")?
            .stdout,
    )
    .unwrap_or_else(|_| "unknown".to_string())
    .trim()
    .to_string();
    let cargo = String::from_utf8(
        ProcessCommand::new("cargo")
            .arg("--version")
            .output()
            .context("run cargo --version")?
            .stdout,
    )
    .unwrap_or_else(|_| "unknown".to_string())
    .trim()
    .to_string();

    let payload = BuildProvenancePayload {
        version: "slsa-provenance.v1".to_string(),
        scope: SENTINEL_ONLY_SCOPE.to_string(),
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        git_head,
        rustc,
        cargo,
        cargo_lock_sha256,
        sbom_sha256,
    };
    let payload_bytes = serde_json::to_vec(&payload).context("serialize provenance payload")?;
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&payload_bytes);

    let (signature_b64, public_key_b64) = match provider {
        SigningProvider::RawB64(secret) | SigningProvider::File(secret) => (
            crate::receipt::sign_payload_b64(secret, &payload_bytes)?,
            crate::receipt::public_key_b64_from_signing_key(secret)?,
        ),
        SigningProvider::KmsCommand(cmd) => (
            run_kms_sign_command(cmd, key_id, &payload_b64)?,
            public_key_b64_override.ok_or_else(|| {
                anyhow!("attest-build: --public-key-b64 required with --kms-sign-cmd")
            })?,
        ),
    };

    let attestation = BuildAttestation {
        statement_type: "https://slsa.dev/provenance/v1".to_string(),
        signature_algorithm: crate::receipt::SIGNATURE_ALGORITHM.to_string(),
        key_id: key_id.to_string(),
        key_source: format!("{:?}", key_source).to_lowercase(),
        payload,
        signature_b64,
        public_key_b64,
    };
    fs::write(
        out_dir.join("build.attestation.slsa.json"),
        format!("{}\n", serde_json::to_string_pretty(&attestation)?),
    )
    .with_context(|| {
        format!(
            "write {}",
            out_dir.join("build.attestation.slsa.json").display()
        )
    })?;
    Ok(())
}

fn verify_build_attestation(path: &Path) -> Result<()> {
    let raw =
        fs::read(path).with_context(|| format!("read attestation file {}", path.display()))?;
    let attestation: BuildAttestation =
        serde_json::from_slice(&raw).context("parse attestation JSON")?;
    let payload = serde_json::to_vec(&attestation.payload).context("serialize payload")?;
    crate::receipt::verify_payload_signature_b64(
        &attestation.public_key_b64,
        &payload,
        &attestation.signature_b64,
    )?;
    if attestation.payload.scope != SENTINEL_ONLY_SCOPE {
        return Err(anyhow!(
            "attestation scope mismatch: expected {}, got {}",
            SENTINEL_ONLY_SCOPE,
            attestation.payload.scope
        ));
    }
    Ok(())
}

fn load_plan(path: &str) -> Result<KKPlan> {
    let s = fs::read_to_string(path).with_context(|| format!("read plan {}", path))?;
    let p: KKPlan = serde_yaml::from_str(&s).with_context(|| "parse plan YAML (strict)")?;
    if p.api_version != "kernelkit.alpha.v0.1" {
        return Err(anyhow!("unsupported api_version: {}", p.api_version));
    }
    Ok(p)
}

fn enforce_policy(p: &KKPlan, applying: bool) -> Result<()> {
    if !applying {
        return Ok(());
    }

    if matches!(p.policy.apply_mode, ApplyMode::ProposeOnly) {
        return Err(anyhow!("policy forbids apply: apply_mode=propose_only"));
    }
    if p.policy.forbid_remote_apply
        && (std::env::var("SSH_CONNECTION").is_ok() || std::env::var("SSH_TTY").is_ok())
    {
        return Err(anyhow!(
            "policy forbids apply from remote session: forbid_remote_apply=true"
        ));
    }
    if p.policy.require_tty_confirm
        && !(atty::is(atty::Stream::Stdin) && atty::is(atty::Stream::Stdout))
    {
        return Err(anyhow!(
            "policy requires interactive TTY confirm: require_tty_confirm=true"
        ));
    }
    if p.policy.allowlist_only {
        enforce_allowlist_only(p)?;
    }
    Ok(())
}

fn enforce_allowlist_only(p: &KKPlan) -> Result<()> {
    const ALLOWED_PREFIXES: [&str; 4] = [
        "/etc/kernel/cmdline.d/",
        "/etc/sysctl.d/",
        "/etc/systemd/system/",
        "/etc/systemd/zram-generator.conf",
    ];
    for path in collect_policy_paths(p) {
        let allowed = ALLOWED_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix));
        if !allowed {
            return Err(anyhow!(
                "policy allowlist_only rejected path outside trusted prefixes: {}",
                path
            ));
        }
    }
    Ok(())
}

fn collect_policy_paths(p: &KKPlan) -> Vec<String> {
    let mut out = vec![
        p.changes.kernel_cmdline.fragment_path.clone(),
        p.changes.sysctl.file_path.clone(),
        p.changes.zram.config_path.clone(),
    ];
    for d in &p.changes.systemd.dropins {
        out.push(format!("/etc/systemd/system/{}.d/{}", d.unit, d.name));
    }
    out.sort();
    out.dedup();
    out
}

fn preflight_json(p: &KKPlan) -> Result<serde_json::Value> {
    let uid = unsafe { libc::geteuid() };
    let is_tty = atty::is(atty::Stream::Stdin) && atty::is(atty::Stream::Stdout);
    let ssh = std::env::var("SSH_CONNECTION").is_ok() || std::env::var("SSH_TTY").is_ok();

    Ok(json!({
        "uid": uid,
        "is_tty": is_tty,
        "is_ssh": ssh,
        "plan_id": p.plan_id,
        "profile": format!("{:?}", p.profile),
        "targets": {
            "os_family": format!("{:?}", p.targets.os_family),
            "kernel_series": p.targets.kernel_series,
            "hardware_tags": p.targets.hardware_tags,
        },
        "paths": {
            "cmdline_fragment": p.changes.kernel_cmdline.fragment_path,
            "sysctl_file": p.changes.sysctl.file_path,
        }
    }))
}

fn snapshot_paths(p: &KKPlan, before_dir: &Path) -> Result<()> {
    let mut paths = Vec::new();
    paths.push(p.changes.kernel_cmdline.fragment_path.clone());
    paths.push(p.changes.sysctl.file_path.clone());

    for d in &p.changes.systemd.dropins {
        let dropin_path = format!("/etc/systemd/system/{}.d/{}", d.unit, d.name);
        paths.push(dropin_path);
    }

    for sp in &p.rollback.snapshot_paths {
        paths.push(sp.clone());
    }

    paths.sort();
    paths.dedup();

    for path in paths {
        let src = PathBuf::from(&path);
        if src.exists() {
            let safe_name = path.trim_start_matches('/').replace('/', "__");
            fs::copy(&src, before_dir.join(safe_name))
                .with_context(|| format!("snapshot {}", src.display()))?;
        }
    }
    Ok(())
}

fn render_apply_sh(p: &KKPlan) -> Result<String> {
    let mut out = String::new();
    out.push_str("#!/usr/bin/env bash\nset -euo pipefail\n\n");
    out.push_str("echo \"KERNELKIT APPLY (v0.1)\"\n\n");

    if p.changes.kernel_cmdline.enabled {
        out.push_str("# kernel cmdline fragment\n");
        out.push_str(&format!(
            "sudo mkdir -p \"{}\"\n",
            parent_dir(&p.changes.kernel_cmdline.fragment_path)
        ));
        out.push_str(&format!(
            "cat > \"{}\" <<'EOF'\n",
            p.changes.kernel_cmdline.fragment_path
        ));
        out.push_str(&render_cmdline_fragment(p));
        out.push_str("EOF\n");
        if p.changes.kernel_cmdline.require_reboot {
            out.push_str("echo \"NOTE: kernel cmdline changed; reboot required\"\n");
        }
        out.push('\n');
    }

    if p.changes.sysctl.enabled {
        out.push_str("# sysctl\n");
        out.push_str(&format!(
            "sudo mkdir -p \"{}\"\n",
            parent_dir(&p.changes.sysctl.file_path)
        ));
        out.push_str(&format!(
            "cat > \"{}\" <<'EOF'\n",
            p.changes.sysctl.file_path
        ));
        for (k, v) in &p.changes.sysctl.set {
            out.push_str(&format!("{k} = {v}\n"));
        }
        out.push_str("EOF\n");
        out.push_str("sudo sysctl --system >/dev/null || true\n");
        out.push('\n');
    }

    if p.changes.systemd.enabled {
        out.push_str("# systemd drop-ins\n");
        for d in &p.changes.systemd.dropins {
            let dir = format!("/etc/systemd/system/{}.d", d.unit);
            let path = format!("{}/{}", dir, d.name);
            out.push_str(&format!("sudo mkdir -p \"{}\"\n", dir));
            out.push_str(&format!("cat > \"{}\" <<'EOF'\n", path));
            out.push_str(&normalize_newlines(&d.content));
            if !d.content.ends_with('\n') {
                out.push('\n');
            }
            out.push_str("EOF\n");
        }
        out.push_str("sudo systemctl daemon-reload || true\n\n");
    }

    if p.changes.zram.enabled {
        out.push_str("# zram generator\n");
        out.push_str(&format!(
            "sudo mkdir -p \"{}\"\n",
            parent_dir(&p.changes.zram.config_path)
        ));
        out.push_str(&format!(
            "cat > \"{}\" <<'EOF'\n",
            p.changes.zram.config_path
        ));
        for (dev, cfg) in &p.changes.zram.settings {
            out.push_str(&format!("[{dev}]\n"));
            out.push_str(&format!("zram-size = {}\n", cfg.zram_size));
            out.push_str(&format!("compression-algorithm = {}\n", cfg.compression));
            out.push_str(&format!("swap-priority = {}\n\n", cfg.swap_priority));
        }
        out.push_str("EOF\n");
        out.push_str(
            "echo \"NOTE: enable/start zram service depends on distro; verify after reboot\"\n\n",
        );
    }

    if p.changes.nvidia.enabled {
        out.push_str("# nvidia (manual steps; v0.1 does not execute)\n");
        out.push_str("echo \"NVIDIA settings requested (v0.1 manual):\"\n");
        out.push_str(&format!(
            "echo \"  persistence_mode={:?}\"\n",
            p.changes.nvidia.settings.persistence_mode
        ));
        out.push_str(&format!(
            "echo \"  power_limit_watts={:?}\"\n",
            p.changes.nvidia.settings.power_limit_watts
        ));
        out.push('\n');
    }

    Ok(out)
}

fn render_rollback_sh(p: &KKPlan) -> Result<String> {
    let mut out = String::new();
    out.push_str("#!/usr/bin/env bash\nset -euo pipefail\n\n");
    out.push_str("echo \"KERNELKIT ROLLBACK (v0.1)\"\n\n");
    out.push_str("BASE_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\n");
    out.push_str("BEFORE_DIR=\"$BASE_DIR/before\"\n\n");

    let mut paths = Vec::new();
    paths.push(p.changes.kernel_cmdline.fragment_path.clone());
    paths.push(p.changes.sysctl.file_path.clone());
    for d in &p.changes.systemd.dropins {
        paths.push(format!("/etc/systemd/system/{}.d/{}", d.unit, d.name));
    }
    for sp in &p.rollback.snapshot_paths {
        paths.push(sp.clone());
    }
    paths.sort();
    paths.dedup();

    out.push_str("restore_file() {\n");
    out.push_str("  local path=\"$1\"\n");
    out.push_str("  local key\n");
    out.push_str("  key=\"${path#/}\"\n");
    out.push_str("  key=\"${key//\\//__}\"\n");
    out.push_str("  local snap=\"$BEFORE_DIR/$key\"\n");
    out.push_str("  if [[ -f \"$snap\" ]]; then\n");
    out.push_str("    echo \"restore: $path\"\n");
    out.push_str("    sudo mkdir -p \"$(dirname \"$path\")\"\n");
    out.push_str("    sudo cp -f \"$snap\" \"$path\"\n");
    out.push_str("  else\n");
    out.push_str("    # file did not exist before; delete only if it's kernelkit-owned\n");
    out.push_str("    if [[ \"$path\" == \"/etc/sysctl.d/99-kernelkit.conf\" || \"$path\" == \"/etc/kernel/cmdline.d/99-kernelkit.conf\" ]]; then\n");
    out.push_str("      echo \"delete: $path\"\n");
    out.push_str("      sudo rm -f \"$path\"\n");
    out.push_str("    fi\n");
    out.push_str("  fi\n");
    out.push_str("}\n\n");

    for path in paths {
        out.push_str(&format!("restore_file \"{}\"\n", path));
    }

    out.push_str("\nsudo systemctl daemon-reload || true\n");
    out.push_str("sudo sysctl --system >/dev/null || true\n");
    if p.changes.kernel_cmdline.enabled && p.changes.kernel_cmdline.require_reboot {
        out.push_str("echo \"NOTE: kernel cmdline rollback may require reboot\"\n");
    }
    Ok(out)
}

fn render_cmdline_fragment(p: &KKPlan) -> String {
    let mut s = String::new();
    s.push_str("# kernelkit cmdline fragment (v0.1)\n");
    s.push_str("# add:\n");
    for a in &p.changes.kernel_cmdline.params.add {
        s.push_str(&format!("#   {a}\n"));
    }
    s.push_str("# remove:\n");
    for r in &p.changes.kernel_cmdline.params.remove {
        s.push_str(&format!("#   {r}\n"));
    }
    s
}

fn parent_dir(path: &str) -> String {
    Path::new(path)
        .parent()
        .unwrap_or(Path::new("/"))
        .display()
        .to_string()
}

fn normalize_newlines(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

fn write_text(path: PathBuf, contents: &str) -> Result<()> {
    fs::write(&path, contents).with_context(|| format!("write {}", path.display()))
}

fn make_executable(path: PathBuf) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms)?;
    }
    Ok(())
}
