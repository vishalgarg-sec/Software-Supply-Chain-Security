# Software Supply Chain Security

## Introduction
A knowledge base comprising **Software Supply Chain Security** initiatives, standards, regulations, organizations, vendors, tooling, books, articles and a plethora of other learning resources from the web. The list was initially compiled to help me with my research for my upcoming book on Software Supply Chain Security. However, I have decided to make the list public for the benefit of everyone else working in this domain. I will endeavour to keep the list up to date as best as I can.

## Organizations, Foundations, Working Groups
### National Telecommunications and Information Administration ([NTIA](https://www.ntia.gov/))
* [NTIA SBOM Resources](https://www.ntia.gov/page/software-bill-materials)
* [SBOM FAQ](https://www.ntia.doc.gov/files/ntia/publications/sbom_faq_-_fork_for_october_22_meeting.pdf)
* [How-To Guide for SBOM Generation](https://www.ntia.gov/files/ntia/publications/howto_guide_for_sbom_generation_v1.pdf)
### Cybersecurity and Infrastructure Security Agency ([CISA](https://www.cisa.gov/))
* [CISA SBOM Resources](https://www.cisa.gov/sbom)
* [Software Bill of Materials (SBOM) Sharing Lifecycle Report](https://www.cisa.gov/sites/default/files/2023-04/sbom-sharing-lifecycle-report_508.pdf), April 2023
* [SBOM-a-rama 2023 Recordings](https://www.cisa.gov/news-events/events/sbom-rama)
* [SBOM-a-rama 2021 Recordings](https://www.cisa.gov/resources-tools/resources/cisa-sbom-rama)
### The White House - Office of the National Cyber Director ([ONCD](https://www.whitehouse.gov/oncd/))
* [Request for Information: Open-Source Software Security: Areas of Long-Term Focus and Prioritization](https://www.regulations.gov/document/ONCD-2023-0002-0001), RFI comments submission deadline: October 9, 2023
* [National Cybersecurity Strategy 2023](https://www.whitehouse.gov/wp-content/uploads/2023/03/National-Cybersecurity-Strategy-2023.pdf)
### National Institute of Standards and Technology ([NIST](https://www.nist.gov/))
* [Improving the Nation's Cybersecurity: NIST’s Responsibilities Under the May 2021 Executive Order](https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity)
* [NIST SP 800-161 Rev.1 - Cybersecurity Supply Chain Risk Management Practices for Systems and Organizations](https://csrc.nist.gov/pubs/sp/800/161/r1/final), May 2022
* [Secure Software Development Framework (SSDF)](https://csrc.nist.gov/Projects/ssdf)
### Open Worldwide Application Security Project ([OWASP](https://owasp.org/))
* [OWASP Software Component Verification Standard](https://owasp.org/www-project-software-component-verification-standard/)
* [OWASP CycloneDX](https://owasp.org/www-project-cyclonedx/)
* [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
* [Article on Component Analysis](https://owasp.org/www-community/Component_Analysis) by [Steve Springett](https://www.linkedin.com/in/stevespringett/)
* [OWASP BOM Maturity Model](https://scvs.owasp.org/bom-maturity-model/)
### Open Source Security Foundation ([OpenSSF](https://openssf.org/))
* [The Open Source Software Security Mobilization Plan](https://openssf.org/oss-security-mobilization-plan/)
* [OpenSSF Working Groups](https://openssf.org/community/openssf-working-groups/)
* [OpenSSF sigstore](https://www.sigstore.dev/)
* [Securing Your Software Supply Chain with Sigstore Course](https://openssf.org/training/securing-your-software-supply-chain-with-sigstore-course/)
* [OpenSSF Scorecard](https://securityscorecards.dev/), [[GitHub](https://github.com/ossf/scorecard)]
### Cloud Native Computing Foundation ([CNCF](https://www.cncf.io/))
* [Software Supply Chain Security](https://github.com/cncf/tag-security/tree/main/supply-chain-security)
* [CNCF Software Supply Chain Best Practices](https://project.linuxfoundation.org/hubfs/CNCF_SSCP_v1.pdf), [[GitHub](https://github.com/cncf/tag-security/blob/main/supply-chain-security/supply-chain-security-paper/CNCF_SSCP_v1.pdf)]
* [Secure Software Factory Reference Architecture](https://github.com/cncf/tag-security/blob/main/supply-chain-security/secure-software-factory/Secure_Software_Factory_Whitepaper.pdf)
### [Software Transparency Foundation](https://st.foundation/)
* [OSSKB.org](https://osskb.org/)

## Regulations
* [EO-14028 - Executive Order on Improving the Nation’s Cybersecurity](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/), May 12, 2021
* [The European Cyber Resilience Act (CRA)](https://www.european-cyber-resilience-act.com/), September 2022

## Standards, Frameworks, Best Practices
* [Supply-chain Levels for Software Artifacts (SLSA)](https://slsa.dev/), [[GitHub](https://github.com/slsa-framework/slsa)], [[Google](https://security.googleblog.com/2021/06/introducing-slsa-end-to-end-framework.html)]
* [OWASP Software Component Verification Standard (SCVS)](https://owasp.org/www-project-software-component-verification-standard/)
* [OASIS Common Security Advisory Framework (CSAF)](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=csaf)
* [NIST Secure Software Development Framework (SSDF)](https://csrc.nist.gov/Projects/ssdf)
* [Cybersecurity Information Sheet (CSI) on Defending Continuous Integration/Continuous Delivery (CI/CD) Environments](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3441780/nsa-and-cisa-best-practices-to-secure-cloud-continuous-integrationcontinuous-de/), National Security Agency (NSA) and Cybersecurity and Infrastructure Security Agency (CISA) joint report, June 2023
* [Securing the Software Supply Chain - Recommended Practices Guide for Developers](https://media.defense.gov/2022/Sep/01/2003068942/-1/-1/0/ESF_SECURING_THE_SOFTWARE_SUPPLY_CHAIN_DEVELOPERS.PDF), Enduring Security Framework (ESF) Software Supply Chain Working Panel, [Critical Infrastructure Partnership Advisory Council (CIPAC)](https://www.cisa.gov/resources-tools/groups/critical-infrastructure-partnership-advisory-council-cipac), August 2022
* [CIS Software Supply Chain Security Guide v1.0](https://www.cisecurity.org/insights/white-papers/cis-software-supply-chain-security-guide), June 2022
* [NIST recommendations on Defending Against Software Supply Chain Attacks](https://www.cisa.gov/sites/default/files/publications/defending_against_software_supply_chain_attacks_508_1.pdf), NIST, April 2021
* [Microsoft Secure Supply Chain Consumption Framework (S2C2F)](https://www.microsoft.com/en-us/security/blog/2022/11/16/microsoft-contributes-s2c2f-to-openssf-to-improve-supply-chain-security/)[[GitHub]](https://github.com/ossf/s2c2f)


## Software Supply Chain Threats
#### Threats
* [SLSA Threats & Mitigations](https://slsa.dev/spec/v1.0/threats)
* [Google article on Software Supply Chain Threats](https://cloud.google.com/software-supply-chain-security/docs/attack-vectors)
* [ODNI Software Supply Chain Attacks - 2023 Edition](https://www.dni.gov/files/NCSC/documents/supplychain/Software-Supply-Chain-Attacks.pdf)
* [ODNI Software Supply Chain Attacks - 2021 Edition](https://www.dni.gov/files/NCSC/documents/supplychain/Software_Supply_Chain_Attacks.pdf)
* [ODNI Software Supply Chain Attacks - 2017 Edition](https://www.dni.gov/files/NCSC/documents/supplychain/20190327-Software-Supply-Chain-Attacks02.pdf)
* [CNCF Catalog of Types of Supply Chain Compromises](https://github.com/cncf/tag-security/blob/main/supply-chain-security/compromises/compromise-definitions.md)
* [MITRE Supply Chain Compromise Techniques](https://attack.mitre.org/techniques/T1195/)
* [CAPEC Supply-Chain Attack Vectors](https://capec.mitre.org/data/definitions/437.html)
* [ENISA Threat Landscape for Supply Chain Attacks](https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks)
* [Atlantic Council's BREAKING TRUST: Shades of Crisis Across an Insecure Software Supply Chain](https://atlanticcouncil.org/wp-content/uploads/2020/07/Breaking-trust-Shades-of-crisis-across-an-insecure-software-supply-chain.pdf)
* [Risk Explorer for Software Supply Chains](https://sap.github.io/risk-explorer-for-software-supply-chains/)
* [Open-Source Software Supply Chain Attack Vectors](https://sap.github.io/risk-explorer-for-software-supply-chains/#/attackvectors)
* [Taxonomy of Attacks on Open-Source Software Supply Chains](https://arxiv.org/abs/2204.04008)
* [Microsoft Open Source Software Supply Chain Threats catalogue](https://www.microsoft.com/en-us/securityengineering/opensource/ossthreats)
#### Attacks / Compromises
* [Worldwide software supply chain attacks tracker (updated daily)](https://www.comparitech.com/software-supply-chain-attacks/)
* [Catalog of Supply Chain Compromises](https://github.com/cncf/tag-security/tree/main/supply-chain-security/compromises)
* [Software Supply Chain Compromises](https://github.com/IQTLabs/software-supply-chain-compromises)
* [A (Partial) History of Software Supply Chain Attacks](https://www.reversinglabs.com/blog/a-partial-history-of-software-supply-chain-attacks)
* [A History of Software Supply Chain Attacks - July 2017–Present](https://www.sonatype.com/resources/vulnerability-timeline)
## Vulnerability Management
##### EPSS
* [Exploit Prediction Scoring System (EPSS)](https://www.first.org/epss/)
##### VEX
* [Vulnerability Exploitability eXchange (VEX)](https://www.ntia.gov/files/ntia/publications/vex_one-page_summary.pdf)
* [OpenVEX Specification](https://github.com/openvex/spec)
* [VEX Use Cases](https://www.cisa.gov/sites/default/files/publications/VEX_Use_Cases_April2022.pdf)
* [VEX Status Justification](https://www.cisa.gov/sites/default/files/publications/VEX_Status_Justification_Jun22.pdf)
##### SSVC
* [CISA Stakeholder Specific Vulnerability Categorization (SSVC)](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc)
##### KEV
* [CISA Known Exploited Vulnerabilities Catalog (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

#### Vulnerability Databases
* [CVE (New)](https://www.cve.org/), [CVE (Old)](https://cve.mitre.org/)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* [The Exploit Database](https://www.exploit-db.com/)
* [Sonatype OSS Index](https://ossindex.sonatype.org/)
* [Open Source Vulnerability Database (OSV)](https://osv.dev/)
* [Global Security Database (GSD)](https://gsd.id/)

## Software Identification
* [Common Platform Enumeration (CPE)](https://csrc.nist.gov/pubs/ir/7697/final)
* [Software Identification (SWID)](https://csrc.nist.gov/projects/Software-Identification-SWID)
* [Package URL (purl)](https://github.com/package-url/purl-spec)

## Bill of Materials (BOM)
* [Software Bill of Materials (SBOM)](https://cyclonedx.org/capabilities/sbom)
* [Software as a Service Bill of Materials (SaaSBOM)](https://cyclonedx.org/capabilities/saasbom)
* [Hardware Bill of Materials (HBOM)](https://cyclonedx.org/capabilities/hbom)
* [Machine Learning Bill of Materials (MLBOM)](https://cyclonedx.org/capabilities/mlbom)
* [Manufacturing Bill of Materials (MBOM)](https://cyclonedx.org/capabilities/mbom)
* [Operations Bill of Materials (OBOM)](https://cyclonedx.org/capabilities/obom)
* [Cryptography Bill of Materials (CBOM)](https://github.com/IBM/CBOM)

## Software Bill of Materials (SBOM)
### Formats and Specifications
* [CycloneDX](https://cyclonedx.org/)
* [Software Package Data Exchange (SPDX)](https://spdx.dev/)
* [Software Identification (SWID)](https://csrc.nist.gov/projects/Software-Identification-SWID)
### SBOM Lifecycle / Implementation Practices
* [GitLab Software Supply Chain Security Direction](https://about.gitlab.com/direction/supply-chain/)

## Tooling
### SBOM Generation
#### Native
#### Open-Source
* [kubernetes bom tool](https://github.com/kubernetes-sigs/bom)
* [Microsoft’s SBOM Tool](https://github.com/microsoft/sbom-tool)
* [spdx-sbom-generator](https://github.com/opensbom-generator/spdx-sbom-generator)
* [syft](https://github.com/anchore/syft)
#### Commercial

### SBOM Scanning & Analysis
#### Native
#### Open-Source
* [OWASP Dependency-Track](https://dependencytrack.org/)
* [Graph for Understanding Artifact Composition (GUAC)](https://guac.sh/), [[GitHub](https://github.com/guacsec/guac)], [[Google Article](https://security.googleblog.com/2022/10/announcing-guac-great-pairing-with-slsa.html)]
* [NTIA Conformance Checker](https://github.com/spdx/ntia-conformance-checker)
#### Commercial

### SBOM Governance
#### Native
#### Open-Source
* [Aqua Chain-bench](https://github.com/aquasecurity/chain-bench/tree/main)
* [SBOM Benchmark](https://sbombenchmark.dev/)
#### Commercial

### Other / Unsorted

## Software Supply Chain Security in the Cloud
### AWS

### Azure

### GCP
* [Google's Software Supply Chain Security documentation](https://cloud.google.com/software-supply-chain-security/docs)

## Vendors
* [Anchore](https://anchore.com/)
* [Binarly](https://www.binarly.io/) - Binarly is the world’s most advanced automated firmware supply chain security platform. Using cutting-edge machine-learning techniques, Binary identifies both known and unknown vulnerabilities, misconfigurations, and malicious code in firmware and hardware components.* [Chainguard](https://www.chainguard.dev/)
* [Codenotary](https://codenotary.com/)
* [Cybeats](https://www.cybeats.com/)
* [Endor Labs](https://www.endorlabs.com/) - At Endor Labs, we've created the first open source dependency lifecycle management platform to help OSS consumers select, secure and maintain dependencies effectively.
* [FOSSA](https://fossa.com/)
* [NetRise](https://www.netrise.io/) - The NetRise Platform is a next-generation product security solution for XIoT devices. Through ML-driven binary analysis, our platform generates industry-best Software Bills of Material (SBOMs), identifies and prioritizes vulnerabilities, and uncovers non-CVE risk that would otherwise go undetected.
* [Rezilion](https://www.rezilion.com/)
* [TestifySec](https://www.testifysec.com/)


## Books
* [Software Supply Chain Security: Securing the End-to-End Supply Chain for Software, Firmware, and Hardware](https://www.amazon.com/Software-Supply-Chain-Security-End/dp/1098133706/) by [Cassie Crossley](https://www.linkedin.com/in/cassiecrossley/), Release date: January 2024
* [Software Transparency - Supply Chain Security in an Era of Software-Driven Society](https://www.amazon.com/Software-Transparency-Security-Software-Driven-Society/dp/1394158483) by [Chris Huges](https://www.linkedin.com/in/resilientcyber/) & [Tony Turner](https://www.linkedin.com/in/tonyturnercissp/), Release date: June 2023


## Industry Reports
* [Snyk State of Open Source Security 2023 Report](https://snyk.io/reports/open-source-security/), Snyk, 2023
* [Sonatype 8th Annual State of the Software Supply Chain report](https://www.sonatype.com/state-of-the-software-supply-chain/introduction), Sonatype
* [Synopsis Open Source Security and Risk Analysis Report](https://www.synopsys.com/software-integrity/resources/analyst-reports/open-source-security-risk-analysis.html), Synopsis, 2023
* [The State of Dependency Management](https://www.endorlabs.com/state-of-dependency-management), Endor Labs, 2023
* [OpenSSF Annual Report](https://openssf.org/wp-content/uploads/sites/132/2022/12/OpenSSF-Annual-Report-2022.pdf), OpenSSF, 2022
* [Software Bill of Materials (SBOM) and Cybersecurity Readiness](https://8112310.fs1.hubspotusercontent-na1.net/hubfs/8112310/LF%20Research/State%20of%20Software%20Bill%20of%20Materials%20-%20Report.pdf), The Linux Foundation, January 2022
* [The State of Enterprise Open Source](https://www.redhat.com/en/enterprise-open-source-report/2022), RedHat, 2022
* [The State of Open Source Security Vulnerabilities](https://www.mend.io/wp-content/media/2021/03/The-state-of-open-source-vulnerabilities-2021-annual-report.pdf), Mend, 2021
* [GSMA Open Source Software Security Research Summary](https://www.gsma.com/security/wp-content/uploads/2020/12/Open-Source-Software-Security-Research-Summary-v1.1.pdf), GSMA, December 2020
* [Snyk State of Open Source Security Report](https://go.snyk.io/rs/677-THP-415/images/State%20Of%20Open%20Source%20Security%20Report%202020.pdf), Snyk, 2020
* [State of Software Security - Open Source Edition](https://www.veracode.com/sites/default/files/pdf/resources/reports/state-of-software-security-open-source-edition-veracode-report.pdf), Veracode, 2020


## Guides / Documentation
* [Authoritative Guide to SBOM](https://cyclonedx.org/guides/sbom/OWASP_CycloneDX-SBOM-Guide-en.pdf), OWASP CycloneDX, June 2023
* [Open Source Supply Chain Security course](https://osssc-edu.github.io/supply-chain.github.io/https://osssc-edu.github.io/supply-chain.github.io/), Course material collected, curated, maintained and structured by PhD students and faculty from the [KTH Royal Institute of Technology](https://www.kth.se/en) in Stockholm, Sweden

## Articles / White Papers
#### Supply Chain Security
* [Fostering Open Source Software Security - Blueprint for a Government Cybersecurity Open Source Program Office](https://www.stiftung-nv.de/sites/default/files/snv_fostering_open_source_software_security.pdf), Stiftung Neue Verantwortung (SNV), May 2023* [Tragedy of the Digital Commons](https://ssrn.com/abstract=4245266), Sharma, Chinmayi, Written: August 2022, Last Revised: May 2023
* [“Always Contribute Back”: A Qualitative Study on Security Challenges of the Open Source Supply Chain](https://saschafahl.de/static/paper/ossc2023.pdf), April 2023
* [Software Supply Chain Attacks An Illustrated Typological Review](https://www.research-collection.ethz.ch/bitstream/handle/20.500.11850/584947/2/Cyber-Reports-2023-01-Software-Supply-Chain-Attacks.pdf), January 2023
* [Taxonomy of Attacks on Open-Source Software Supply Chains](https://arxiv.org/pdf/2204.04008.pdf), April 2022
* [On Systematics of the Information Security of Software Supply Chains](https://link.springer.com/chapter/10.1007/978-3-030-63322-6_9), December 2020
* [BREAKING TRUST: Shades of Crisis Across an Insecure Software Supply Chain](https://www.atlanticcouncil.org/wp-content/uploads/2020/07/Breaking-trust-Shades-of-crisis-across-an-insecure-software-supply-chain.pdf), July 2020
* [Supply Chain Integrity: An overview of the ICT supply chain risks and challenges, and vision for the way forward](https://www.enisa.europa.eu/publications/sci-2015), CISA, September 2015
#### SBOM
* [Principles and Practices for Software Bill of Materials for Medical Device Cybersecurity](https://www.imdrf.org/sites/default/files/2023-04/Principles%20and%20Practices%20for%20Software%20Bill%20of%20Materials%20for%20Medical%20Device%20Cybersecurity%20%28N73%29.pdf),  Medical Device Cybersecurity Working Group, International Medical Device Regulators Forum, April 2023
* [An Empirical Study on Software Bill of Materials: Where We Stand and the Road Ahead](https://arxiv.org/pdf/2301.05362.pdf), February 2023
* [Using the Software Bill of Materials for Enhancing Cybersecurity](https://english.ncsc.nl/binaries/ncsc-en/documenten/publications/2021/february/4/using-the-software-bill-of-materials-for-enhancing-cybersecurity/Final+Report+SBoM+for+Cybersecurity+v1.0.pdf), Capgemini, January 2021
#### Unsorted

## Git Projects
* [Malicious Dependencies](https://github.com/jeremylong/malicious-dependencies)

## Blogs
* [Resilient Cyber](https://resilientcyber.substack.com/) by Chris Huges
* [Tom Alrich's blog](http://tomalrichblog.blogspot.com/) by Tom Alrich
* [Endor Labs resources](https://www.endorlabs.com/resources-overview)
* [Chainguard blog](https://www.chainguard.dev/unchained)
* [snyk blog](https://snyk.io/blog/?tag=open-source-security)
* [TestifySec blog](https://www.testifysec.com/blog/)


## Webinars
* [Endor Labs webinars](https://www.endorlabs.com/resources-overview)

## Podcasts
* [daBOM](https://dabom.captivate.fm/)
## Events
* [OpenSSF Day Europe, Bilbao, Spain – 18 September 2023](https://openssf.org/event/openssf-day-europe-september-18-in-bilbao-spain/)

## From the Web
### Readings
* [The history of cybersecurity](https://blog.avast.com/history-of-cybersecurity-avast)
* [Lessons Not Learned From Software Supply Chain Attacks](https://www.darkreading.com/attacks-breaches/lessons-not-learned-from-software-supply-chain-attacks)
* [SBOM 101 - Answering the questions I was afraid to ask](https://sysdig.com/blog/sbom-101-software-bill-of-materials/)
* [“SBOM” should not exist! Long live the SBOM.](https://medium.com/@steve_springett/sbom-should-not-exist-long-live-the-sbom-4554d5c31ff9)
* [SLSA dip — At the Source of the problem!](https://medium.com/boostsecurity/slsa-dip-source-of-the-problem-a1dac46a976)
* [Are SBOMs any good? Preliminary measurement of the quality of open source project SBOMs](https://www.chainguard.dev/unchained/are-sboms-any-good-preliminary-measurement-of-the-quality-of-open-source-project-sboms)
* [I am not a supplier](https://www.softwaremaxims.com/blog/not-a-supplier)
* [Making the Cyber Resilience Act work for open source software developers](https://github.blog/wp-content/uploads/2023/03/GitHub_Position_Paper-Cyber_Resilience_Act.pdf)
* [Introducing The Top 10 Open Source Software (OSS) Risks](https://www.endorlabs.com/blog/introducing-the-top-10-open-source-software-oss-risks)
* [Software supply chain attacks – everything you need to know](https://portswigger.net/daily-swig/software-supply-chain-attacks-everything-you-need-to-know)
* [What is an SBOM, and why should you Care??](https://boxboat.com/2021/05/12/what-is-sbom-and-why-should-you-care/)
* [Software Bill Of Materials (SBOM) Formats, Use Cases, and Specifications](https://fossa.com/blog/software-bill-of-materials-formats-use-cases-tools/)
* [Are you ready with your SBOM ? Think again !](https://nadgowdas.github.io/blog/2021/trust-sbom/)
* [What an SBOM can do for you](https://www.chainguard.dev/unchained/what-an-sbom-can-do-for-you)
* [Comparing SBOM Standards: SPDX vs. CycloneDX](https://blog.sonatype.com/comparing-sbom-standards-spdx-vs.-cyclonedx-vs.-swid)
* [GitHub blog post on Introducing npm package provenance](https://github.blog/2023-04-19-introducing-npm-package-provenance/)
### Presentations
* [BlackHat Presentation - Reflections on Trust in the Software Supply Chain](https://i.blackhat.com/BH-US-23/Presentations/US-23-Long-Reflections-On-Trust.pdf) by [Jeremy Long](https://www.blackhat.com/us-23/briefings/schedule/speakers.html#jeremy-long-31926), August 2023
* [Flaming Hot SLSA!](https://speakerdeck.com/abhaybhargav/flaming-hot-slsa) by [Abhay Bhargav](https://www.linkedin.com/in/abhaybhargav/), 2022
* [MITRE Software Bill of Materials (SBOM) Presentation](https://csrc.nist.gov/CSRC/media/Projects/cyber-supply-chain-risk-management/documents/SSCA/Spring_2019/8MayAM2.3_Software_Bill_of_Materials_Robert_Martin_05_08_19_clean.pdf), 2019

### Videos
* [Why you need an XBOM – the eXtended Software Bill of Materials](https://www.youtube.com/watch?v=KPa-v5KndIY)

## Related GitHub Repos
* [bureado / awesome-software-supply-chain-security](https://github.com/bureado/awesome-software-supply-chain-security)
* [meta-fun / awesome-software-supply-chain-security](https://github.com/meta-fun/awesome-software-supply-chain-security)
* [awesomeSBOM / awesome-sbom](https://github.com/awesomeSBOM/awesome-sbom)
* [AevaOnline / supply-chain-synthesis](https://github.com/AevaOnline/supply-chain-synthesis/)
* [IQTLabs / software-supply-chain-compromises](https://github.com/IQTLabs/software-supply-chain-compromises)

## Miscellaneous / Unsorted


