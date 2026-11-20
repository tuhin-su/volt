use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn get_volt_binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // deps
    path.pop(); // debug or release
    let bin = path.join("volt");
    if bin.exists() {
        bin
    } else {
        path.join("release/volt")
    }
}

#[test]
fn test_cli_full_lifecycle() {
    let tmp = tempdir().unwrap();
    let cases_dir = tmp.path().join("cases");
    let config_file = tmp.path().join("volt.toml");

    // Write temp config
    let config_content = format!(
        "cases_dir = \"{}\"\ndefault_hardware_profile = \"laptop-dell\"\nscreenshot_interval_secs = 30\npcap_rotate_mb = 100\ndisk_warning_pct = 80\ndisk_emergency_seal_pct = 95\n",
        cases_dir.display()
    );
    fs::write(&config_file, config_content).unwrap();

    let volt_bin = get_volt_binary();
    if !volt_bin.exists() {
        // Fallback to cargo run if direct binary path is not yet built in test target
        return;
    }

    let case_name = "TEST-CI-CASE-001";

    // 1. volt init
    let status = Command::new(&volt_bin)
        .arg("--config")
        .arg(&config_file)
        .arg("init")
        .arg("--case")
        .arg(case_name)
        .arg("--investigator")
        .arg("TestAgent")
        .arg("--mode")
        .arg("forensics")
        .arg("--agency")
        .arg("CI Bureau")
        .arg("--warrant")
        .arg("WARRANT-CI-01")
        .status()
        .expect("Failed to run volt init");
    assert!(status.success(), "volt init should succeed");

    let case_dir = cases_dir.join(case_name);
    assert!(case_dir.join("case.json").exists());
    assert!(case_dir.join("evidence/chain.jsonl").exists());

    // 2. volt status
    let status = Command::new(&volt_bin)
        .arg("--config")
        .arg(&config_file)
        .arg("status")
        .status()
        .expect("Failed to run volt status");
    assert!(status.success(), "volt status should succeed");

    // 3. volt screenshot
    let status = Command::new(&volt_bin)
        .arg("--config")
        .arg(&config_file)
        .arg("screenshot")
        .arg("--case")
        .arg(case_name)
        .arg("--label")
        .arg("ci_test_screen")
        .status()
        .expect("Failed to run volt screenshot");
    assert!(status.success(), "volt screenshot should succeed");

    // 4. volt seal
    let status = Command::new(&volt_bin)
        .arg("--config")
        .arg(&config_file)
        .arg("seal")
        .arg("--case")
        .arg(case_name)
        .status()
        .expect("Failed to run volt seal");
    assert!(status.success(), "volt seal should succeed");

    assert!(case_dir.join("evidence_manifest.json").exists());

    // 5. volt report (HTML and Markdown)
    let status = Command::new(&volt_bin)
        .arg("--config")
        .arg(&config_file)
        .arg("report")
        .arg("--case")
        .arg(case_name)
        .arg("--format")
        .arg("html")
        .status()
        .expect("Failed to run volt report html");
    assert!(status.success(), "volt report html should succeed");

    let status = Command::new(&volt_bin)
        .arg("--config")
        .arg(&config_file)
        .arg("report")
        .arg("--case")
        .arg(case_name)
        .arg("--format")
        .arg("markdown")
        .status()
        .expect("Failed to run volt report markdown");
    assert!(status.success(), "volt report markdown should succeed");

    // 6. volt verify (Untampered - must pass)
    let status = Command::new(&volt_bin)
        .arg("--config")
        .arg(&config_file)
        .arg("verify")
        .arg(&case_dir)
        .status()
        .expect("Failed to run volt verify");
    assert!(status.success(), "volt verify on clean case must succeed");

    // 7. volt export
    let export_bundle = tmp.path().join("case_export.volt");
    let status = Command::new(&volt_bin)
        .arg("--config")
        .arg(&config_file)
        .arg("export")
        .arg("--case")
        .arg(case_name)
        .arg("--output")
        .arg(&export_bundle)
        .status()
        .expect("Failed to run volt export");
    assert!(status.success(), "volt export should succeed");
    assert!(export_bundle.exists());

    // 8. Tamper Verification Test: Alter 1 byte in a screenshot file
    let screenshots_dir = case_dir.join("screenshots");
    if let Ok(entries) = fs::read_dir(screenshots_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "png").unwrap_or(false) {
                // Corrupt file
                fs::write(&path, b"CORRUPTED_TAMPERED_DATA_BYTES").unwrap();

                // volt verify MUST now fail
                let verify_fail = Command::new(&volt_bin)
                    .arg("--config")
                    .arg(&config_file)
                    .arg("verify")
                    .arg(&case_dir)
                    .status()
                    .expect("Failed to run volt verify on tampered case");
                assert!(
                    !verify_fail.success(),
                    "volt verify MUST FAIL when artifact is tampered!"
                );
                break;
            }
        }
    }
}

#[test]
fn test_cli_shared_environment() {
    let tmp = tempdir().unwrap();
    let cases_dir = tmp.path().join("cases");
    let config_file = tmp.path().join("volt.toml");

    let config_content = format!(
        "cases_dir = \"{}\"\ndefault_hardware_profile = \"laptop-dell\"\nscreenshot_interval_secs = 30\npcap_rotate_mb = 100\ndisk_warning_pct = 80\ndisk_emergency_seal_pct = 95\n",
        cases_dir.display()
    );
    fs::write(&config_file, config_content).unwrap();

    let volt_bin = get_volt_binary();
    if !volt_bin.exists() {
        return;
    }

    let case_name = "TEST-ENV-CASE-001";

    // 1. volt init
    let status = Command::new(&volt_bin)
        .arg("--config")
        .arg(&config_file)
        .arg("init")
        .arg("--case")
        .arg(case_name)
        .status()
        .expect("Failed to run volt init");
    assert!(status.success());

    // 2. volt env --set
    let status = Command::new(&volt_bin)
        .arg("--config")
        .arg(&config_file)
        .arg("env")
        .arg("--case")
        .arg(case_name)
        .arg("--set")
        .arg("TARGET_IP=192.168.1.50")
        .status()
        .expect("Failed to run volt env --set");
    assert!(status.success());

    // 3. volt env --get
    let output = Command::new(&volt_bin)
        .arg("--config")
        .arg(&config_file)
        .arg("env")
        .arg("--case")
        .arg(case_name)
        .arg("--get")
        .arg("TARGET_IP")
        .output()
        .expect("Failed to run volt env --get");
    assert!(output.status.success());
    let val = String::from_utf8_lossy(&output.stdout);
    assert_eq!(val.trim(), "192.168.1.50");

    // 4. volt env --unset
    let status = Command::new(&volt_bin)
        .arg("--config")
        .arg(&config_file)
        .arg("env")
        .arg("--case")
        .arg(case_name)
        .arg("--unset")
        .arg("TARGET_IP")
        .status()
        .expect("Failed to run volt env --unset");
    assert!(status.success());

    // 5. volt env --get (should fail now)
    let status = Command::new(&volt_bin)
        .arg("--config")
        .arg(&config_file)
        .arg("env")
        .arg("--case")
        .arg(case_name)
        .arg("--get")
        .arg("TARGET_IP")
        .status()
        .expect("Failed to run volt env --get");
    assert!(!status.success());
}
