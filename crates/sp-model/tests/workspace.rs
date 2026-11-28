use std::fs;
use std::path::PathBuf;

#[test]
fn workspace_lints_forbid_unsafe() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let text = fs::read_to_string(root).expect("read root Cargo.toml");
    let mut in_table = false;
    let mut found = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_table = line == "[workspace.lints.rust]";
            continue;
        }
        if in_table {
            let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            if compact == "unsafe_code=\"forbid\"" {
                found = true;
            }
        }
    }
    assert!(found, "[workspace.lints.rust] must set unsafe_code = \"forbid\"");
}
