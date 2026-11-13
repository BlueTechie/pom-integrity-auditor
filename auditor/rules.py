from dataclasses import dataclass
from auditor.parser import Dependency, Repository


@dataclass
class Finding:
    severity: str
    rule_id: str
    target: str
    message: str


def check_repositories(repos: list[Repository]) -> list[Finding]:
    ''' Looks for URLs without TLS for repos and non-official repos '''
    findings = []
    for r in repos:
        if (r.url.startswith("http://")):
            findings.append(Finding(
                severity = "HIGH",
                rule_id = "REPO-01",
                target = f"{r.id} ({r.url})",
                message = "Repository uses plaintext HTTP. Vulnerable to MitM binary injection" \
                            " (CVE-2021-26291).",
            ))
        
        # Check if a non-central custom repo is defined (shadowing / poisoning risk)
        if ("repo.maven.apache.org" not in r.url and "repo1.maven.org" not in r.url):
            findings.append(Finding(
                severity = "MEDIUM",
                rule_id = "REPO-02",
                target = f"{r.id} ({r.url})",
                message = "Custom repository declared. Ensure repository order does not allow dependency"\
                            " shadowing.",
            ))

    return findings


def check_versions(deps: list[Dependency]) -> list[Finding]:
    ''' Looks for missing versions, dynamic versions (LATEST or RELEASE), floating range and 
        unresolved versions'''
    findings = []
    for d in deps:
        coord = f"{d.group_id}:{d.artifact_id}"
        
        if (d.version is None):
            findings.append(Finding(
                severity = "LOW",
                rule_id = "VER-01",
                target = coord,
                message = "Missing explicit version (verify the lock state).",
            ))
            continue

        if (d.version == "LATEST" or d.version == "RELEASE"):
            findings.append(Finding(
                severity = "HIGH",
                rule_id = "VER-02",
                target = f"{coord}:{d.version}",
                message = "Dynamic meta-version used. Builds are non-reproducible and an attacker"\
                            " could tamper with newest versions.",
            ))
        elif (d.version.startswith("[") or d.version.startswith("(")):
            findings.append(Finding(
                severity = "MEDIUM",
                rule_id = "VER-03",
                target = f"{coord}:{d.version}",
                message = "Floating version range used instead of pinned version.",
            ))
        elif (d.version.startswith("${")):
            findings.append(Finding(
                severity = "LOW",
                rule_id = "VER-04",
                target = f"{coord}:{d.version}",
                message = "Unresolved Maven property in version string.",
            ))

    return findings