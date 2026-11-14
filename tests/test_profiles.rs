use tempfile::tempdir;
use volt::hwgen::HardwareProfile;

#[test]
fn test_all_hardware_profiles() {
    let profiles = vec![
        HardwareProfile::virtualbox(),
        HardwareProfile::dell_latitude(),
        HardwareProfile::hp_elitedesk(),
    ];

    for profile in profiles {
        assert!(!profile.name.is_empty());
        assert!(!profile.hostname.is_empty());
        assert!(!profile.mac_address.is_empty());
        assert!(!profile.product_name.is_empty());
        assert!(!profile.board_vendor.is_empty());
        assert!(!profile.bios_version.is_empty());
        assert!(!profile.cpu_model.is_empty());
        assert!(profile.cpu_cores > 0);

        // Verify write_spoof_tree creates all files
        let tmp = tempdir().unwrap();
        let spoof = tmp.path().join("spoof");
        profile.write_spoof_tree(&spoof).unwrap();

        assert!(spoof.join("etc/hostname").exists());
        assert!(spoof.join("etc/machine-id").exists());
        assert!(spoof.join("etc/os-release").exists());
        assert!(spoof.join("etc/passwd").exists());
        assert!(spoof.join("etc/shadow").exists());
        assert!(spoof.join("proc/cpuinfo").exists());
        assert!(spoof.join("proc/version").exists());
        assert!(spoof.join("sys/class/dmi/id/product_name").exists());
        assert!(spoof.join("sys/class/dmi/id/board_vendor").exists());
        assert!(spoof.join("sys/class/dmi/id/bios_version").exists());
    }
}
