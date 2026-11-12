import sys
from auditor.parser import parse_pom


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m auditor.cli <path-to-pom.xml>")
        sys.exit(1)

    pom_path = sys.argv[1]
    deps, repos = parse_pom(pom_path)

    print(f"Found {len(deps)} dependencies and {len(repos)} custom repositories:\n")
    for r in repos:
        print(f" [REPO] {r.id} -> {r.url}")
    for d in deps:
        print(f" [DEP]  {d.group_id}:{d.artifact_id} (version: {d.version})")


if __name__ == "__main__":
    main()