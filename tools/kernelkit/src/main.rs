mod normalize;
mod plan;
mod receipt;
mod verify;

use anyhow::{anyhow, Context, Result};
use chrono::{SecondsFormat, Utc};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    plan::{ApplyMode, Plan as KKPlan, PromotionReceiptPayload},
    receipt::{
        build_signed_receipt, build_trust_root_from_signing_key, sha256_hex,
        write_receipt_template, write_trust_root_template, SENTINEL_ONLY_SCOPE,
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
    },
    SignReceipt {
        apply_dir: String,
        #[arg(long)]
        signing_key_b64: String,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        out: Option<String>,
        #[arg(long)]
        trust_root_out: Option<String>,
        #[arg(long)]
        issued_at: Option<String>,
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
        } => {
            let dir = PathBuf::from(apply_dir);
            let outcome = verify_apply_dir(
                &dir,
                &VerifyOptions {
                    receipt_path: receipt.map(PathBuf::from),
                    trust_root_path: trust_root.map(PathBuf::from),
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
            key_id,
            out,
            trust_root_out,
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
            let receipt = build_signed_receipt(payload, key_id.clone(), &signing_key_b64)?;
            let out_path = out
                .map(PathBuf::from)
                .unwrap_or_else(|| dir.join("promotion.receipt.json"));
            fs::write(
                &out_path,
                format!("{}\n", serde_json::to_string_pretty(&receipt)?),
            )
            .with_context(|| format!("sign-receipt: write {}", out_path.display()))?;
            let trust_root = build_trust_root_from_signing_key(&signing_key_b64, key_id)?;
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
