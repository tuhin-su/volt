use tempfile::tempdir;
use volt::core::session::SessionInfo;

#[test]
fn test_session_lifecycle_and_terminals() {
    let tmp = tempdir().unwrap();
    let session_file = tmp.path().join(".active_session.json");

    let mut session = SessionInfo::new(
        "CASE-MULTI-01",
        "sess-uuid-1234",
        1001,
        "laptop-dell",
        "red-team",
    );
    session.tcpdump_pid = Some(1002);
    session.active_terminals.push("subterminal_1".to_string());
    session.active_terminals.push("subterminal_2".to_string());

    session.save(&session_file).unwrap();
    assert!(session_file.exists());

    let loaded = SessionInfo::load(&session_file).unwrap();
    assert_eq!(loaded.case_name, "CASE-MULTI-01");
    assert_eq!(loaded.pid, 1001);
    assert_eq!(loaded.tcpdump_pid, Some(1002));
    assert_eq!(loaded.operation_mode, "red-team");
    assert_eq!(loaded.active_terminals.len(), 3);
}
