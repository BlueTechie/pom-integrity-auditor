from dataclasses import dataclass
from typing import Optional
# Avoid xml bombs (see https://en.wikipedia.org/wiki/Billion_laughs_attack)
from defusedxml.ElementTree import parse 

# Maven POMs (almost) always use the 4.0.0 namespace
NS = {"mvn": "http://maven.apache.org/POM/4.0.0"}


@dataclass
class Dependency:
    group_id: str
    artifact_id: str
    version: Optional[str] = None
    scope: Optional[str] = None


@dataclass
class Repository:
    id: str
    url: str


def _get_text(element, tag: str) -> Optional[str]:
    node = element.find(f"mvn:{tag}", NS)
    # Fallback in case the pom.xml doesn't declare the xmlns header
    if (node is None):
        node = element.find(tag)
    if (node is not None and node.text):
        return node.text.strip()
    return None


def parse_pom(file_path: str):
    tree = parse(file_path)
    root = tree.getroot()

    deps = []
    # Find all <dependency> blocks inside <dependencies>
    dep_nodes = root.findall(".//mvn:dependencies/mvn:dependency", NS)
    if (dep_nodes == []):
        dep_nodes = root.findall(".//dependencies/dependency")
    
    for d in dep_nodes:
        group = _get_text(d, "groupId")
        artifact = _get_text(d, "artifactId")
        if (group and artifact):
            deps.append(Dependency(
                group_id=group,
                artifact_id=artifact,
                version=_get_text(d, "version"),
                scope=_get_text(d, "scope"),
            ))

    repos = []
    repo_nodes = root.findall(".//mvn:repositories/mvn:repository", NS)
    if (repo_nodes == []):
        repo_nodes = root.findall(".//repositories/repository")
    
    for r in repo_nodes:
        repo_id = _get_text(r, "id") 
        if (repo_id is None):
            repo_id = "unknown"
        url = _get_text(r, "url")
        if (url):
            repos.append(Repository(id=repo_id, url=url))

    return deps, repos