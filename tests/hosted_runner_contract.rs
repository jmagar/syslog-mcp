use std::path::Path;

#[test]
fn all_workflow_runner_selectors_are_github_hosted() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0;
    for entry in std::fs::read_dir(root.join(".github/workflows")).unwrap() {
        let path = entry.unwrap().path();
        if !matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("yml" | "yaml")
        ) {
            continue;
        }
        let workflow = std::fs::read_to_string(&path).unwrap();
        for line in workflow.lines() {
            if let Some(selector) = line.trim().strip_prefix("runs-on:") {
                assert!(
                    matches!(selector.trim(), "ubuntu-24.04" | "windows-latest"),
                    "{} has an unaudited runner selector: {selector}",
                    path.display()
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 0, "no runner selectors were checked");
}

#[test]
fn repository_contract_keeps_pinned_validation_without_private_runner() {
    let workflow = include_str!("../.github/workflows/repository-contract.yml");
    for required in [
        "name: Repository Contract",
        "needs: [contract]",
        "if: always()",
        "repository: dinglebear-ai/workflows",
        "ref: d1a41a7af9c41189e0f1062234364f5814bda99d",
        "python3 workflow-library/scripts/fleet_contract.py check",
        "--repo target",
        "--profile rust",
        "if [[ \"$RESULT\" != \"success\" ]]",
        "exit 1",
    ] {
        assert!(workflow.contains(required), "missing contract: {required}");
    }
    assert!(!workflow.contains("secrets: inherit"));
    assert!(
        !workflow.contains("uses: dinglebear-ai/workflows/.github/workflows/fleet-contract.yml")
    );
}
