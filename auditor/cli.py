import sys
from auditor.parser import parse_pom
from auditor.rules import check_repositories, check_versions


def main():
    if (len(sys.argv) < 2):
        print("Usage: python -m auditor.cli <path-to-pom.xml>")
        sys.exit(1)

    pom_path = sys.argv[1]
    deps, repos = parse_pom(pom_path)

    print(f"Parsed {len(deps)} dependencies and {len(repos)} repositories.\n")

    findings = []
    findings.extend(check_repositories(repos))
    findings.extend(check_versions(deps))

    if (findings == []):
        print("No security issues detected.")
        sys.exit(0)

    print(f"Found {len(findings)} potential supply-chain issues:\n")
    for f in findings:
        print(f"[{f.severity}] {f.rule_id} | {f.target}")
        print(f"  -> {f.message}\n")


if (__name__ == "__main__"):
    main()