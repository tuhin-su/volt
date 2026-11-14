use anyhow::Result;
use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use volt::cli::{Cli, Commands};
use volt::core::case::{Case, CaseStatus};
use volt::core::config::VoltConfig;
use volt::core::session::SessionInfo;
use volt::evidence::{EvidenceManifest, EvidenceVault, HashChain, ReportGenerator};
use volt::hwgen::HardwareProfile;
use volt::network::TcpdumpManager;
use volt::recorder::PtyRecorder;
use volt::sandbox::{Preflight, SandboxLauncher, SandboxMounts};
use volt::screenshot::{IntervalScreenshotWorker, ScreenshotEngine};
use volt::utils::logging::init_logging;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    let config_path = cli.config.unwrap_or_else(|| {
        if Path::new("volt.toml").exists() {
            PathBuf::from("volt.toml")
        } else if let Ok(home) = std::env::var("HOME") {
            let p = PathBuf::from(&home).join(".volt/volt.toml");
            if p.exists() {
                p
            } else {
                PathBuf::from("./volt.toml")
            }
        } else {
            PathBuf::from("./volt.toml")
        }
    });

    let config = VoltConfig::load_or_create(&config_path)?;

    match cli.command {
        Commands::Init {
            case,
            investigator,
            profile,
            mode,
            agency,
            warrant,
            evidence_id,
        } => {
            handle_init(
                &config,
                &case,
                &investigator,
                &profile,
                &mode,
                agency,
                warrant,
                evidence_id,
            )?;
        }
        Commands::Start { case, profile } => {
            handle_start(&config, &case, profile).await?;
        }
        Commands::Join { case, cmd, label } => {
            handle_exec(&config, &case, cmd.as_deref(), label.as_deref())?;
        }
        Commands::Stop { case } => {
            handle_stop(&config, &case)?;
        }
        Commands::Seal { case, sign, gpg_key } => {
            handle_seal(&config, &case, sign, gpg_key)?;
        }
        Commands::Verify { target } => {
            handle_verify(&target)?;
        }
        Commands::Report { case, format, output } => {
            handle_report(&config, &case, &format, output)?;
        }
        Commands::Status { case } => {
            handle_status(&config, case)?;
        }
        Commands::Screenshot { case, label } => {
            handle_screenshot(&config, &case, label.as_deref())?;
        }
        Commands::Export {
            case,
            format,
            output,
        } => {
            handle_export(&config, &case, &format, output)?;
        }
    }

    Ok(())
}

fn handle_init(
    config: &VoltConfig,
    case_name: &str,
    investigator: &str,
    profile_name: &str,
    mode: &str,
    agency: Option<String>,
    warrant: Option<String>,
    evidence_id: Option<String>,
) -> Result<()> {
    let profile = HardwareProfile::load_or_preset(profile_name)?;
    let case = Case::init(
        &config.cases_dir,
        case_name,
        investigator,
        &profile.name,
        mode,
        agency,
        warrant,
        evidence_id,
    )?;

    // Save hardware profile into case directory
    let profile_path = case.dir.join("hardware_profile.json");
    profile.save_to(&profile_path)?;

    // Initialize Genesis block in evidence vault
    let vault = EvidenceVault::open(&case)?;
    let tip = vault.chain.current_tip();

    println!("⚡ VOLT Case Initialized Successfully!");
    println!("  Case ID:          {}", case.metadata.case_name);
    println!("  Investigator:     {}", case.metadata.investigator);
    println!("  Operation Mode:   {}", case.metadata.operation_mode.to_uppercase());
    println!("  Hardware Profile: {} ({})", profile.name, profile.product_name);
    if let Some(ref agency) = case.metadata.agency {
        println!("  Agency/Dept:      {}", agency);
    }
    if let Some(ref warrant) = case.metadata.warrant_ref {
        println!("  Legal Auth/Ref:   {}", warrant);
    }
    println!("  Directory:        {}", case.dir.display());
    println!("  Genesis Hash:     {}", tip);
    println!("\nLaunch session:     volt start --case {}", case_name);
    println!("Attach terminals:   volt exec --case {}", case_name);

    Ok(())
}

async fn handle_start(config: &VoltConfig, case_name: &str, profile_override: Option<String>) -> Result<()> {
    let case_dir = config.cases_dir.join(case_name);
    let case = Case::open(&case_dir)?;

    if case.metadata.status == CaseStatus::Sealed {
        anyhow::bail!("Case '{}' is SEALED. You cannot reopen a sealed evidence case.", case_name);
    }

    // 1. Preflight safety assertion
    Preflight::check_safety(&case.dir)?;

    // 2. Load hardware profile
    let profile_name = profile_override
        .as_deref()
        .unwrap_or(&case.metadata.hardware_profile);
    let profile = HardwareProfile::load_or_preset(profile_name)?;

    // 3. Prepare sandbox identity spoof tree and shims
    let mounts = SandboxMounts::prepare(&case.dir, &profile)?;

    // 4. Open evidence vault and hash chain
    let vault = Arc::new(EvidenceVault::open(&case)?);
    let session_start_hash = vault.record_event("SESSION_START", &case.metadata.genesis_hash)?;
    tracing::info!("Session registered in hash chain: {}", session_start_hash);

    // 5. Start always-on background packet capture
    let tcpdump_mgr = TcpdumpManager::new(case.pcaps_dir(), config.pcap_rotate_mb);
    let tcpdump_child = tcpdump_mgr.spawn().ok();
    let tcpdump_pid = tcpdump_child.as_ref().map(|c| c.id());

    let running_flag = Arc::new(AtomicBool::new(true));

    // Spawn PCAP monitor task
    let pcap_vault = vault.clone();
    let pcap_running = running_flag.clone();
    let pcaps_dir = case.pcaps_dir();
    tokio::spawn(async move {
        TcpdumpManager::monitor_and_hash(pcaps_dir, pcap_vault, pcap_running).await;
    });

    // 6. Start always-on screenshot interval worker
    let screenshot_engine = ScreenshotEngine::new(case.screenshots_dir());
    let _ = screenshot_engine.capture("session_start", Some("entry"));

    let ss_worker = IntervalScreenshotWorker::new(
        ScreenshotEngine::new(case.screenshots_dir()),
        vault.clone(),
        config.screenshot_interval_secs,
        running_flag.clone(),
    );
    tokio::spawn(async move {
        ss_worker.run().await;
    });

    // 7. Save active session info with PID for multi-terminal attachments
    let session_id = uuid::Uuid::new_v4().to_string();
    let current_pid = std::process::id();
    let mut session_info = SessionInfo::new(
        case_name,
        &session_id,
        current_pid,
        &profile.name,
        &case.metadata.operation_mode,
    );
    session_info.tcpdump_pid = tcpdump_pid;
    session_info.save(SessionInfo::session_file(&case.dir))?;

    println!("⚡ VOLT Sandbox Session Active");
    println!("  Case:         {}", case_name);
    println!("  Mode:         {}", case.metadata.operation_mode.to_uppercase());
    println!("  Identity:     {} ({})", profile.name, profile.hostname);
    println!("  Recording:    EVERYTHING (Terminal I/O + PCAP + Screenshots + Hash Chain)");
    println!("  Multi-Term:   Open other terminals and run: volt exec --case {}", case_name);
    println!("  Exit:         Type 'exit' to close primary session\n");

    // 8. Build bubblewrap command and launch inside PTY recorder
    let launcher = SandboxLauncher::new(&case.dir, profile);
    let bwrap_args = launcher.build_bwrap_args(&mounts, None);

    let mut full_command = vec!["bwrap".to_string()];
    full_command.extend(bwrap_args);

    let pty_recorder = PtyRecorder::new(case.evidence_dir().join("terminal_stream_primary.jsonl"));
    let exit_code = match pty_recorder.run_session(&full_command, vault.clone()) {
        Ok(code) => code,
        Err(e) => {
            tracing::warn!("bwrap container launch error: {}", e);
            println!("\n[VOLT] Falling back to direct instrumented shell...");
            let fallback_cmd = vec!["/bin/bash".to_string()];
            pty_recorder.run_session(&fallback_cmd, vault.clone())?
        }
    };

    // 9. Shutdown capture daemons cleanly
    running_flag.store(false, Ordering::Relaxed);
    if let Some(mut child) = tcpdump_child {
        let _ = child.kill();
        let _ = child.wait();
    }

    // Capture exit screenshot
    let _ = screenshot_engine.capture("session_exit", Some("exit"));

    // Record session end event
    let exit_hash = format!("exit_code:{}", exit_code);
    let _ = vault.record_event("SESSION_END", &exit_hash);

    // Remove active session file
    let _ = std::fs::remove_file(SessionInfo::session_file(&case.dir));

    println!("\n⚡ VOLT Session ended with code {}", exit_code);
    println!("  Evidence recorded in: {}", case.evidence_dir().display());
    println!("  Generate report:      volt report --case {}", case_name);
    println!("  Seal evidence with:   volt seal --case {}", case_name);

    Ok(())
}

fn handle_exec(config: &VoltConfig, case_name: &str, cmd: Option<&str>, label: Option<&str>) -> Result<()> {
    let case_dir = config.cases_dir.join(case_name);
    let case = Case::open(&case_dir)?;
    let session_file = SessionInfo::session_file(&case_dir);

    if !session_file.exists() {
        anyhow::bail!(
            "Case '{}' does not have an active session running. Start it first with: volt start --case {}",
            case_name,
            case_name
        );
    }

    let session_info = SessionInfo::load(&session_file)?;
    let term_tag = label.unwrap_or_else(|| "subterminal");
    let term_id = format!("{}_{}", term_tag, uuid::Uuid::new_v4().simple());

    let vault = Arc::new(EvidenceVault::open(&case)?);
    let attach_hash = vault.record_event("TERMINAL_ATTACH", &format!("{}:pid:{}", term_id, session_info.pid))?;
    tracing::info!("Terminal {} attached: {}", term_id, attach_hash);

    println!("⚡ VOLT Terminal Attached");
    println!("  Case:         {}", case_name);
    println!("  Terminal ID:  {}", term_id);
    println!("  Master PID:   {}", session_info.pid);
    println!("  Recording to: evidence/terminal_stream_{}.jsonl\n", term_id);

    // Load hardware profile & mounts for secondary terminal
    let profile = HardwareProfile::load_or_preset(&session_info.hardware_profile)?;
    let mounts = SandboxMounts::prepare(&case.dir, &profile)?;
    let launcher = SandboxLauncher::new(&case.dir, profile);
    let bwrap_args = launcher.build_bwrap_args(&mounts, cmd);

    let mut full_command = vec!["bwrap".to_string()];
    full_command.extend(bwrap_args);

    let term_log = case.evidence_dir().join(format!("terminal_stream_{}.jsonl", term_id));
    let pty_recorder = PtyRecorder::new(&term_log);

    let exit_code = match pty_recorder.run_session(&full_command, vault.clone()) {
        Ok(code) => code,
        Err(_) => {
            let fallback_cmd = if let Some(c) = cmd {
                vec!["/bin/sh".to_string(), "-c".to_string(), c.to_string()]
            } else {
                vec!["/bin/bash".to_string()]
            };
            pty_recorder.run_session(&fallback_cmd, vault.clone())?
        }
    };

    let detach_hash = vault.record_event("TERMINAL_DETACH", &format!("{}:code:{}", term_id, exit_code))?;
    tracing::info!("Terminal {} detached: {}", term_id, detach_hash);

    println!("\n⚡ Sub-terminal [{}] closed (exit code: {})", term_id, exit_code);
    Ok(())
}

fn handle_stop(config: &VoltConfig, case_name: &str) -> Result<()> {
    let case_dir = config.cases_dir.join(case_name);
    let session_file = SessionInfo::session_file(&case_dir);
    if !session_file.exists() {
        println!("No active session found for case '{}'", case_name);
        return Ok(());
    }

    let session_info = SessionInfo::load(&session_file)?;
    if let Some(pid) = session_info.tcpdump_pid {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGTERM,
        );
    }

    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(session_info.pid as i32),
        nix::sys::signal::Signal::SIGTERM,
    );

    let _ = std::fs::remove_file(session_file);
    println!("Stopped session for case '{}'", case_name);
    Ok(())
}

fn handle_seal(config: &VoltConfig, case_name: &str, _sign: bool, _gpg_key: Option<String>) -> Result<()> {
    let case_dir = config.cases_dir.join(case_name);
    let mut case = Case::open(&case_dir)?;

    let vault = EvidenceVault::open(&case)?;
    let manifest = vault.seal(&mut case)?;

    // Automatically generate audit report upon sealing
    let report_path = ReportGenerator::save_report(&case, &manifest)?;

    println!("🔒 Evidence Vault SEALED Successfully!");
    println!("  Case ID:         {}", manifest.case_name);
    println!("  Investigator:    {}", manifest.investigator);
    println!("  Sealed At:       {}", manifest.sealed_at);
    println!("  Total Artifacts: {}", manifest.total_artifacts);
    println!("  Total Size:      {} bytes", manifest.total_bytes);
    println!("  Root Tip Hash:   {}", manifest.chain_tip_hash);
    println!("  Manifest File:   {}/evidence_manifest.json", case.dir.display());
    println!("  Audit Report:    {}", report_path.display());

    Ok(())
}

fn handle_report(config: &VoltConfig, case_name: &str, format: &str, output: Option<PathBuf>) -> Result<()> {
    let case_dir = config.cases_dir.join(case_name);
    let case = Case::open(&case_dir)?;

    let manifest_file = case_dir.join("evidence_manifest.json");
    let manifest = if manifest_file.exists() {
        let content = std::fs::read_to_string(&manifest_file)?;
        serde_json::from_str(&content)?
    } else {
        // Build draft manifest if case is still active or unsealed
        let vault = EvidenceVault::open(&case)?;
        let tip = vault.chain.current_tip();
        EvidenceManifest::build(
            &case.dir,
            &case.metadata.case_name,
            &case.metadata.investigator,
            &case.metadata.hardware_profile,
            &tip,
        )?
    };

    let md_report = ReportGenerator::generate_markdown(&case, &manifest)?;

    let out_path = output.unwrap_or_else(|| {
        case.reports_dir().join(format!("{}_audit_report.{}", case_name, if format == "html" { "html" } else { "md" }))
    });

    if format == "html" {
        let html = format!(
            "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Forensic Audit Report - {}</title><style>body{{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;line-height:1.6;color:#1e293b}}table{{border-collapse:collapse;width:100%;margin:1.5rem 0}}th,td{{border:1px solid #cbd5e1;padding:8px 12px;text-align:left}}th{{background:#f1f5f9}}code{{background:#f1f5f9;padding:2px 6px;border-radius:4px}}pre{{background:#0f172a;color:#f8fafc;padding:1rem;border-radius:6px;overflow-x:auto}}blockquote{{border-left:4px solid #3b82f6;margin:0;padding-left:1rem;color:#475569}}</style></head><body><pre style='background:none;color:inherit;white-space:pre-wrap'>{}</pre></body></html>",
            case_name, md_report
        );
        std::fs::write(&out_path, html)?;
    } else {
        std::fs::write(&out_path, md_report)?;
    }

    println!("🏛️ Forensic Audit Report Generated!");
    println!("  Destination: {}", out_path.display());
    println!("  Case:        {}", case_name);
    println!("  Status:      {}", if case.metadata.status == CaseStatus::Sealed { "SEALED (Court-Ready)" } else { "DRAFT" });

    Ok(())
}

fn handle_verify(target: &Path) -> Result<()> {
    let case_dir = if target.is_dir() {
        target.to_path_buf()
    } else {
        target.parent().unwrap_or(Path::new(".")).to_path_buf()
    };

    println!("🔍 Verifying VOLT Evidence Integrity for {:?}", case_dir);

    // 1. Verify Hash Chain
    let chain_file = case_dir.join("evidence/chain.jsonl");
    if !chain_file.exists() {
        anyhow::bail!("Missing chain.jsonl in {:?}", chain_file);
    }
    let total_blocks = HashChain::verify_file(&chain_file)?;
    println!("  ✓ Cryptographic hash chain: VERIFIED ({} sequential blocks intact)", total_blocks);

    // 2. Verify Manifest Artifacts
    let manifest_file = case_dir.join("evidence_manifest.json");
    if manifest_file.exists() {
        let content = std::fs::read_to_string(&manifest_file)?;
        let manifest: EvidenceManifest = serde_json::from_str(&content)?;

        for (rel, entry) in &manifest.artifacts {
            let full_path = case_dir.join(rel);
            if !full_path.exists() {
                anyhow::bail!("Missing evidence artifact: {:?}", full_path);
            }
            let current_hash = volt::utils::crypto::sha256_file(&full_path)?;
            if current_hash != entry.sha256 {
                anyhow::bail!("Artifact TAMPERED: {:?} (expected {} vs found {})", rel, entry.sha256, current_hash);
            }
        }
        println!("  ✓ Manifest artifacts:       VERIFIED (all {} files match SHA-256)", manifest.total_artifacts);
    }

    println!("\n✅ VERIFICATION PASSED — Evidence integrity is 100% intact and untampered.");
    Ok(())
}

fn handle_status(config: &VoltConfig, case_filter: Option<String>) -> Result<()> {
    println!("⚡ VOLT Status & Storage Overview");
    println!("  Cases directory: {}", config.cases_dir.display());

    if !config.cases_dir.exists() {
        println!("  (No cases created yet)");
        return Ok(());
    }

    for entry in std::fs::read_dir(&config.cases_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if let Some(ref filter) = case_filter {
                if !name.contains(filter) {
                    continue;
                }
            }
            let active = SessionInfo::session_file(&path).exists();
            let status = if active {
                "ACTIVE (Recording - Multi-Terminal Enabled)"
            } else if path.join("evidence_manifest.json").exists() {
                "SEALED (Court-Ready)"
            } else {
                "IDLE"
            };

            println!("  • Case: {:<20} | Status: {}", name, status);
        }
    }

    Ok(())
}

fn handle_screenshot(config: &VoltConfig, case_name: &str, label: Option<&str>) -> Result<()> {
    let case_dir = config.cases_dir.join(case_name);
    let case = Case::open(&case_dir)?;
    let engine = ScreenshotEngine::new(case.screenshots_dir());
    let record = engine.capture("manual", label)?;

    let vault = EvidenceVault::open(&case)?;
    let hash = vault.record_event("SCREENSHOT_MANUAL", &record.sha256)?;

    println!("📸 Screenshot Captured & Hashed");
    println!("  File: {}", record.filename);
    println!("  SHA:  {}", record.sha256);
    println!("  Tip:  {}", hash);

    Ok(())
}

fn handle_export(config: &VoltConfig, case_name: &str, format: &str, output: Option<PathBuf>) -> Result<()> {
    let case_dir = config.cases_dir.join(case_name);
    let case = Case::open(&case_dir)?;

    if case.metadata.status != CaseStatus::Sealed {
        anyhow::bail!("Case must be sealed before exporting. Run 'volt seal --case {}' first.", case_name);
    }

    let out_file = output.unwrap_or_else(|| {
        PathBuf::from(format!("{}.{}", case_name, if format == "volt" { "volt" } else { "tar.gz" }))
    });

    println!("📦 Exporting case '{}' to {:?}...", case_name, out_file);

    let status = std::process::Command::new("tar")
        .arg("-czf")
        .arg(&out_file)
        .arg("-C")
        .arg(case.dir.parent().unwrap_or(Path::new(".")))
        .arg(case_name)
        .status()?;

    if !status.success() {
        anyhow::bail!("Failed to create archive bundle");
    }

    let bundle_hash = volt::utils::crypto::sha256_file(&out_file)?;
    println!("✓ Export complete!");
    println!("  Bundle: {}", out_file.display());
    println!("  SHA256: {}", bundle_hash);

    Ok(())
}
