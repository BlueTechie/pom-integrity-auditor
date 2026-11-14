# pom-integrity-auditor

This CLI tool secures vulnerable Project Object Model (`pom.xml`) files from Java Maven projects against various supply chain attacks. 

For context: Among other functionality, the `pom.xml` file defines all the dependencies a Java project needs. For this reason, it is also the primary entrypoint for attacks that inject malicious code from dependencies. 

## Motivation
Supply chain attacks are currently (as of 2026) a wide-spread problem in Software Security - see the [Axios](https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/axios-npm-package-compromised), [Shai-Hulud](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/) and [TanStack](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem) attacks this year alone for just a few high-impact examples.

## Scope and disclaimer
This tool does not protect a Maven project against all supply chain attacks for a simple reason: It can be (and often is!) the case that malicious code finds its way in a project from **legitimate** dependencies, when for instance a malicious PR is accepted into the dependency's codebase early on in its development. Checking every single line of code of all dependencies is not in scope for a small CLI tool of this nature (and would be a more fitting task for tools such as a virus scanner).

There are, however, numerous other attacks that can be detected without looking at the code of the dependencies. This class of attacks is due to misconfiguration of the `pom.xml` file and has been made more visible in the start of the 2020-s (see [Birsan's medium post](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)).

## Threat model
This tool therefore assumes the following threat model with adversary _Mallory_: 
1) The **intended** dependency with its **intended** version does not contain vulnerabilities that are relevant to the project that downloads it. This means that we assume that widely used legitimate dependencies under a specific version number do not contain hidden malware, as mentioned above.
2) _Mallory_ is able to create malicious copies of legitimate dependencies and publish them under a slightly different name (such as `lodasch` instead of `lodash`). This type of attack has the amazing name _Typosquatting_.
3) _Mallory_ can publish on repository `C` a malicious version of dependency `A` that is normally hosted on repository `B`. Bonus points if the version on repository `C` is "higher" syntactically than on repository `B`, since in that case Maven chooses the malicious version over the legitimate one when the version is unpinned.
4) _Mallory_ can host malicious Maven repositories. The official Maven repository is _Maven Central_, although other legitimate repositories exist.
5) Hearing insecure HTTP (non-TLS) traffic is music in _Mallory_'s ears and they can inject malicious code that way.

## Checks performed
The integrity auditor performs these checks and provides an audit of its findings:
[TBA]

