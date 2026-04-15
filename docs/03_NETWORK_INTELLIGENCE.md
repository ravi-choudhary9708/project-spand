# 03 — Network Intelligence & Asset Classification

QuantumShield doesn't just scan certificates; it analyzes the **network context** of every asset to help security teams prioritize their response based on asset proximity and exposure.

## Asset Classification Tiers

Every discovered asset is assigned one of four network types:

| Tier | Icon | Meaning | Security Context |
| :--- | :--- | :--- | :--- |
| **Internal** | 🔒 | RFC 1918 / 4193 private IP | **High Risk.** This asset is not meant to be public. |
| **CDN Protected** | 🛡️ | Cloudflare, Akamai, Fastly, etc. | Protected by a WAF. Path B bypass is required. |
| **Restricted** | 🚧 | Resolved to Public IP but no response | Firewalled or closed ports. |
| **Public** | 🌐 | Reachable Public Asset | Standard public-facing infrastructure. |

---

##  Data Leak Detection (CWE-200)

One of QuantumShield's advanced intelligence features is the automated detection of **Infrastructure Exposure**. 

If a domain resolves to an **Internal** IP address but was found in public Certificate Transparency (CT) logs, the system triggers a **Medium Severity Finding**:
- **CWE ID**: CWE-200 (Exposure of Sensitive Information)
- **Problem**: The organization has accidentally leaked internal network topology (private hostnames/IPs) to public databases.
- **Impact**: Attackers can use this information to map out the internal network for lateral movement once they breach the perimeter.

---

## 🌐 DNS & Infrastructure Detection

The scanner explicitly probes **Port 53 (TCP)**. This allows it to identify:
- Authoritative DNS servers.
- Recursive resolvers.
- Active Directory / BIND infrastructure.

These assets are categorized under the **DNS Infrastructure** service category and prioritized for quantum-safe migration, as the entire chain of trust (DNSSEC) relies on the cryptographic strength of these root nodes.
