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


def _extract_properties(root) -> dict:
    ''' Many POMs declare version variables in the properties block '''
    props = {}
    props_node = root.find("mvn:properties", NS)
    if (props_node is None):
        props_node = root.find("properties")
    
    if (props_node is not None):
        for child in props_node:
            # Strip namespace prefix like {http://maven...}spring.version
            tag_name = child.tag
            if ("}" in tag_name):
                tag_name = tag_name.split("}", 1)[1]
            if (child.text):
                props[tag_name] = child.text.strip()
                
    return props


def _resolve_value(val: Optional[str], props: dict) -> Optional[str]:
    ''' Helper that checks if there is a variable in the properties for that val '''
    if (val is None):
        return None
    if (val.startswith("${") and val.endswith("}")):
        prop_key = val[2:-1]
        if (prop_key in props):
            return props[prop_key]
    return val


def parse_pom(file_path: str):
    tree = parse(file_path)
    root = tree.getroot()

    props = _extract_properties(root)

    deps = []
    # Find all <dependency> blocks inside <dependencies>
    dep_nodes = root.findall(".//mvn:dependencies/mvn:dependency", NS)
    if (dep_nodes == []):
        dep_nodes = root.findall(".//dependencies/dependency")
    
    for d in dep_nodes:
        group = _get_text(d, "groupId")
        artifact = _get_text(d, "artifactId")
        raw_version = _get_text(d, "version")
        resolved_version = _resolve_value(raw_version, props)

        if (group and artifact):
            deps.append(Dependency(
                group_id = group,
                artifact_id = artifact,
                version = resolved_version,
                scope = _get_text(d, "scope"),
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
            repos.append(Repository(id = repo_id, url = url))

    return deps, repos