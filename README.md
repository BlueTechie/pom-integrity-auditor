# POM Integrity Auditor

This CLI tool scans vulnerable Project Object Model (`pom.xml`) files from Java Maven projects for various supply chain vulnerabilities. 

For context: Among other functionality, the `pom.xml` file defines all the dependencies a Java project needs. For this reason, it is also the primary entrypoint for attacks that inject malicious code from dependencies. 

## Usage
Invoke this tool with the following command:
```bash
python -m auditor.cli file_to_test.xml
```

Among other tests, the auditor queries Maven Central for the existence of all dependencies and ensures that all domains resolve correctly. If you wish to disable these features, append the `--offline` flag.

The `/tests` folder contains a few examples of vulnerable POM files, such as `vulnerable_pom_2.xml`.


## Motivation
Supply chain attacks are currently (as of 2026) a wide-spread problem in Software Security - see the [Axios](https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/axios-npm-package-compromised), [Shai-Hulud](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/) and [TanStack](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem) attacks for just a few recent high-impact examples. 

The Maven ecosystem in particular is also not spared from these types of attacks - see for instance the [Shai-Hulud v2](https://thehackernews.com/2025/11/shai-hulud-v2-campaign-spreads-from-npm.html). Furthermore, [Reyes et al.](https://dl.acm.org/doi/10.1145/3733827.3765523) introduced the concept of and showed a proof of concept for Maven-Hijack, a class of shadowing attacks which exploit the order in which Maven resolves classes from dependencies.

## Scope and Disclaimer
This tool does not protect a Maven project against all supply chain attacks for a simple reason: It can be (and often is!) the case that malicious code finds its way in a project from **legitimate** dependencies, when for instance a malicious PR is accepted into the dependency's codebase early on in its development. Checking every single line of code of all dependencies is not in scope for a small CLI tool of this nature (and would be a more fitting task for tools such as a malware scanner).

There are, however, numerous other attacks that can be detected without looking at the code of the dependencies. This class of attacks is due to misconfiguration of the `pom.xml` file and has been made more visible in the start of the 2020s (see [Birsan's medium post](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)).

## Threat Model
This tool therefore assumes the following threat model with adversary _Mallory_: 
1) The **intended** dependency with its **intended** version does not contain vulnerabilities that are relevant to the project that downloads it. This means that we assume that widely used legitimate dependencies under a specific version number do not contain hidden malware, as mentioned above.
2) _Mallory_ is able to create malicious copies of legitimate dependencies and publish them under a slightly different name (such as `lodasch` instead of `lodash`). This type of attack has the amazing name _Typosquatting_.
3) _Mallory_ can publish on repository `C` a malicious version of dependency `A` that is normally hosted on repository `B`. Bonus points if the version on repository `C` is "higher" syntactically than on repository `B`, since in that case Maven chooses the malicious version over the legitimate one when the version is unpinned.
4) _Mallory_ can host malicious Maven repositories. The official Maven repository is _Maven Central_, although other legitimate repositories exist.
5) Insecure HTTP (non-TLS) traffic is music to_Mallory_'s ears and they can inject malicious code that way.

## Checks Performed
The integrity auditor performs a few checks and provides an audit of its findings. The tool scans the `pom.xml` file for:
- **repo URLs without TLS**. This is supported by Maven 3.8.0 and below, which makes a Man-In-The-Middle attack possible (by redirection to a malicious domain).
- **non-official repos** (i.e., not from Maven Central). This makes the project vulnerable to shadowing attacks such as the ones mentioned in the **Motivation** section above if custom repositories are active.
- **Dead or expired repo domains**. An attacker can then hijack that domain and inject malicious code into the project.
- **missing version numbers**. Since Maven prioritizes a higher version, an attacker could perform the attack described in point 3 of the **Threat Model** section. 
- **dynamic versions (LATEST or RELEASE)**. Same as the point above.
- **floating ranges**. Same as the point above 
- **unresolved versions**. Same as the point above.
- **typos in dependency names**. For this, the Levenshtein distance to the few dozen most popular dependencies is computed and typos of edit distance 1 or 2 are detected.
-  **namespace Hijacking**. If the dependency code is pulled from GitHub instead of Maven Central and the author changed its username or deleted their account, an attacker can claim that username and repo name instead.
- **dependency Confusion**. If a malicious dependency with the same name as a project-internal one is found on Maven Central with a higher version number, the Maven Central one will get chosen first.
- Additional checks **TBA**.

