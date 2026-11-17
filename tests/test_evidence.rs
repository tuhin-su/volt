use tempfile::tempdir;
use volt::core::case::Case;
use volt::evidence::{EvidenceVault, HashChain};
use volt::hwgen::HardwareProfile;
use volt::utils::crypto::sha256_bytes;

#[test]
fn test_case_init_and_genesis() {
    let tmp = tempdir().unwrap();
    let profile = HardwareProfile::virtualbox();
    let case = Case::init(
        tmp.path(),
        "CASE-TEST-001",
        "AgentSmith",
        &profile.name,
        "forensics",
        Some("DOJ-Cyber".to_string()),
        Some("WARRANT-2026-99A".to_string()),
        Some("EVID-001".to_string()),
    )
    .unwrap();

    assert_eq!(case.metadata.case_name, "CASE-TEST-001");
    assert_eq!(case.metadata.investigator, "AgentSmith");

    let vault = EvidenceVault::open(&case).unwrap();
    let tip = vault.chain.current_tip();
    assert_eq!(tip.len(), 64);
}

#[test]
fn test_hashchain_tamper_detection() {
    let tmp = tempdir().unwrap();
    let chain_path = tmp.path().join("chain.jsonl");

    let chain = HashChain::open_or_init(&chain_path, "genesis_seed_123").unwrap();
    chain.append("CMD", &sha256_bytes(b"nmap -sS 10.0.0.1")).unwrap();
    chain.append("PCAP", &sha256_bytes(b"packet_data_chunk")).unwrap();
    chain.append("SCREENSHOT", &sha256_bytes(b"screenshot_png_bytes")).unwrap();

    // Verify intact chain
    let count = HashChain::verify_file(&chain_path).unwrap();
    assert_eq!(count, 4); // Genesis + 3 events

    // Tamper with chain file (modify an event type or hash byte)
    let content = std::fs::read_to_string(&chain_path).unwrap();
    let tampered = content.replacen("\"CMD\"", "\"TAMPERED\"", 1);
    assert_ne!(content, tampered, "String replacement must have altered content");
    std::fs::write(&chain_path, tampered).unwrap();

    // Verification MUST FAIL
    let result = HashChain::verify_file(&chain_path);
    assert!(result.is_err(), "Verification should have caught tampering!");
}

#[test]
fn test_hardware_spoof_tree() {
    let tmp = tempdir().unwrap();
    let profile = HardwareProfile::dell_latitude();
    let spoof_dir = tmp.path().join("spoof");

    profile.write_spoof_tree(&spoof_dir).unwrap();

    let product_name = std::fs::read_to_string(spoof_dir.join("sys/class/dmi/id/product_name")).unwrap();
    assert_eq!(product_name.trim(), "Latitude 5520");

    let hostname = std::fs::read_to_string(spoof_dir.join("etc/hostname")).unwrap();
    assert!(hostname.trim().starts_with("DESKTOP-"));

    let hosts = std::fs::read_to_string(spoof_dir.join("etc/hosts")).unwrap();
    assert!(hosts.contains("localhost"));
    assert!(hosts.contains(&hostname.trim()));
}

#[test]
fn test_sandbox_gui_and_fontconfig_mounts() {
    let tmp = tempdir().unwrap();
    let profile = HardwareProfile::virtualbox();
    let mounts = volt::sandbox::SandboxMounts::prepare(tmp.path(), &profile).unwrap();
    let launcher = volt::sandbox::SandboxLauncher::new(tmp.path(), profile);
    let args = launcher.build_bwrap_args(&mounts, None);

    // Verify Fontconfig configuration is mounted
    assert!(args.iter().any(|a| a == "/etc/fonts"));
    assert!(args.iter().any(|a| a == "/var/cache/fontconfig"));

    // Verify POSIX shared memory and X11 unix sockets
    assert!(args.iter().any(|a| a == "/dev/shm"));
    assert!(args.iter().any(|a| a == "/tmp/.X11-unix"));

    // Verify browser nested-sandbox overrides
    assert!(args.iter().any(|a| a == "MOZ_DISABLE_CONTENT_SANDBOX"));
    assert!(args.iter().any(|a| a == "MOZ_DISABLE_SANDBOX"));
    assert!(args.iter().any(|a| a == "ELECTRON_DISABLE_SANDBOX"));
    assert!(args.iter().any(|a| a == "NO_AT_SPI_BUS"));
    assert!(args.iter().any(|a| a == "SESSION_MANAGER"));
    assert!(args.iter().any(|a| a == "/opt"));

    // Verify application shims were generated and made executable
    let shim_firefox = tmp.path().join("shims/bin/firefox");
    assert!(shim_firefox.exists());
    let shim_content = std::fs::read_to_string(&shim_firefox).unwrap();
    assert!(shim_content.contains("MOZ_DISABLE_CONTENT_SANDBOX=1"));

    let shim_chrome = tmp.path().join("shims/bin/google-chrome");
    assert!(shim_chrome.exists());
    let shim_chromium = tmp.path().join("shims/bin/chromium");
    assert!(shim_chromium.exists());
    let shim_brave = tmp.path().join("shims/bin/brave");
    assert!(shim_brave.exists());
    let shim_code = tmp.path().join("shims/bin/code");
    assert!(shim_code.exists());

    // Verify network tool shims (nmap, ping, masscan)
    assert!(args.iter().any(|a| a == "VOLT_RAW_SOCKETS"));
    let shim_nmap = tmp.path().join("shims/bin/nmap");
    assert!(shim_nmap.exists());
    let nmap_content = std::fs::read_to_string(&shim_nmap).unwrap();
    assert!(nmap_content.contains("--unprivileged"));

    let shim_ping = tmp.path().join("shims/bin/ping");
    assert!(shim_ping.exists());
    let shim_masscan = tmp.path().join("shims/bin/masscan");
    assert!(shim_masscan.exists());

    // Verify privilege escalation & package guidance shims
    assert!(tmp.path().join("shims/bin/sudo").exists());
    assert!(tmp.path().join("shims/bin/su").exists());
    assert!(tmp.path().join("shims/bin/doas").exists());
    assert!(tmp.path().join("shims/bin/pkexec").exists());
    assert!(tmp.path().join("shims/bin/apt").exists());

    // Verify scratch mounts
    assert!(args.iter().any(|a| a == "/var/tmp"));
    assert!(args.iter().any(|a| a == "/run/lock"));
}

#[test]
fn test_report_with_short_payload_hashes() {
    let tmp = tempdir().unwrap();
    let profile = HardwareProfile::virtualbox();
    let case = Case::init(
        tmp.path(),
        "REPORT-TEST-001",
        "InvestigatorAlice",
        &profile.name,
        "forensics",
        None,
        None,
        None,
    )
    .unwrap();

    let vault = EvidenceVault::open(&case).unwrap();
    // Append events with varying payload lengths, including short ones (< 16 chars)
    vault.record_event("SESSION_START", "full_64_character_sha256_genesis_hash_placeholder_1234567890abcdef").unwrap();
    vault.record_event("SESSION_END", "exit_code:1").unwrap(); // length 11 — previously panicked!
    vault.record_event("CUSTOM_SHORT", "abc").unwrap();        // length 3
    vault.record_event("EMPTY_EVENT", "").unwrap();             // length 0

    let tip = vault.chain.current_tip();
    let manifest = volt::evidence::EvidenceManifest::build(
        &case.dir,
        &case.metadata.case_name,
        &case.metadata.investigator,
        &case.metadata.hardware_profile,
        &tip,
    )
    .unwrap();

    // Must not panic on short payload strings
    let report = volt::evidence::ReportGenerator::generate_markdown(&case, &manifest).unwrap();
    assert!(report.contains("REPORT-TEST-001"));
    assert!(report.contains("exit_code:1"));
    assert!(report.contains("CUSTOM_SHORT"));
}

#[test]
fn test_default_cases_dir_tilde_expansion() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let default_dir = volt::core::config::default_case_dir();
    assert_eq!(default_dir, std::path::PathBuf::from(home).join(".cases"));

    let expanded = volt::core::config::expand_tilde("~/.cases/test-case");
    assert!(!expanded.to_string_lossy().starts_with("~"));
    assert!(expanded.to_string_lossy().ends_with(".cases/test-case"));
}

#[test]
fn test_sudo_user_case_resolution() {
    std::env::set_var("SUDO_USER", "testuser");
    let path = volt::core::config::expand_tilde("~/.cases/test");
    assert!(path.to_string_lossy().contains(".cases/test"));
    std::env::remove_var("SUDO_USER");
}
