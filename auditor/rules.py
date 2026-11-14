import json
import socket
import urllib.request
import urllib.parse
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from auditor.parser import Dependency, Repository

# Known safe public prefixes we don't need to query for Dependency Confusion
TRUSTED_PUBLIC_PREFIXES = (
    "org.springframework",
    "org.apache",
    "com.google",
    "com.fasterxml",
    "org.junit",
    "junit",
    "org.slf4j",
    "ch.qos.logback",
    "org.mockito",
    "org.projectlombok",
    "commons-",
    "javax.",
    "jakarta.",
)


@dataclass
class Finding:
    severity: str
    rule_id: str
    target: str
    message: str


def _load_popular_artifacts() -> list[str]:
    ''' Loads baseline popular Maven coordinates from local JSON file '''
    data_path = Path(__file__).parent / "data" / "popular_maven.json"
    if (not data_path.exists()):
        return []
    with open(data_path, "r", encoding = "utf-8") as f:
        return json.load(f)


def _levenshtein(s1: str, s2: str) -> int:
    ''' Classic dynamic programming edit distance between two strings '''
    if (len(s1) < len(s2)):
        return _levenshtein(s2, s1)
    if (len(s2) == 0):
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def _domain_resolves(url: str) -> bool:
    ''' Checks if the hostname in a repository URL actually resolves in DNS '''
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    if (host is None):
        return False
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False


def check_repositories(repos: list[Repository], check_dns: bool = True) -> list[Finding]:
    ''' Looks for URLs without TLS, non-official repos, and dead/expired repo domains '''
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
        is_central = ("repo.maven.apache.org" in r.url or "repo1.maven.org" in r.url)
        if (not is_central):
            findings.append(Finding(
                severity = "MEDIUM",
                rule_id = "REPO-02",
                target = f"{r.id} ({r.url})",
                message = "Custom repository declared. Ensure repository order does not allow dependency" \
                            " shadowing.",
            ))

            if (check_dns and not _domain_resolves(r.url)):
                findings.append(Finding(
                    severity = "HIGH",
                    rule_id = "REPO-03",
                    target = f"{r.id} ({r.url})",
                    message = "Custom repository domain failed DNS resolution (NXDOMAIN). Potential" \
                                " expired domain hijacking vector.",
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


def check_typosquatting(deps: list[Dependency]) -> list[Finding]:
    ''' Flags dependencies with small edit distance (1 or 2) to popular Maven packages '''
    popular = _load_popular_artifacts()
    findings = []

    for d in deps:
        coord = f"{d.group_id}:{d.artifact_id}"
        if (coord in popular):
            continue

        for pop in popular:
            dist = _levenshtein(coord, pop)
            if (dist > 0 and dist <= 2):
                findings.append(Finding(
                    severity = "HIGH",
                    rule_id = "SQUAT-01",
                    target = coord,
                    message = f"Suspected typosquatting of popular artifact '{pop}' (edit distance = {dist}).",
                ))

    return findings


def _exists_on_maven_central(group_id: str, artifact_id: str) -> Optional[bool]:
    ''' Queries Maven Central Solr API to check if groupId:artifactId is publicly registered '''
    query = urllib.parse.quote(f'g:"{group_id}" AND a:"{artifact_id}"')
    url = f"https://search.maven.org/solrsearch/select?q={query}&rows=1&wt=json"
    
    try:
        req = urllib.request.Request(url, headers = {"User-Agent": "pom-integrity-auditor/0.1"})
        with urllib.request.urlopen(req, timeout = 5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            num_found = data.get("response", {}).get("numFound", 0)
            return (num_found > 0)
    except Exception:
        return None


def check_dependency_confusion(deps: list[Dependency], has_custom_repos: bool) -> list[Finding]:
    ''' Checks if non-standard dependencies exist on Maven Central. Flags potential namespace 
        hijacking / dependency confusion vectors '''
    findings = []
    for d in deps:
        if (d.group_id.startswith(TRUSTED_PUBLIC_PREFIXES)):
            continue

        coord = f"{d.group_id}:{d.artifact_id}"
        exists = _exists_on_maven_central(d.group_id, d.artifact_id)
        
        if (exists == False):
            if (d.group_id.startswith("io.github.") or d.group_id.startswith("com.github.")):
                findings.append(Finding(
                    severity = "HIGH",
                    rule_id = "CONF-01",
                    target = coord,
                    message = "Unclaimed GitHub-based groupId on Maven Central. If the GitHub username" \
                                " is unregistered/renamed, an attacker can claim it and publish malicious jars.",
                ))
            elif (has_custom_repos):
                findings.append(Finding(
                    severity = "HIGH",
                    rule_id = "CONF-01",
                    target = coord,
                    message = "Artifact not found on Maven Central while custom repositories are active." \
                                " Verify domain/namespace ownership to prevent Dependency Confusion.",
                ))
            else:
                findings.append(Finding(
                    severity = "LOW",
                    rule_id = "CONF-02",
                    target = coord,
                    message = "Artifact does not exist on public Maven Central (likely private/internal).",
                ))

    return findings