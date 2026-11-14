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
}
