# 08 — AI Remediation Engine: Intelligent Migration

The **AI Remediation Engine** is QuantumShield's advanced advisory layer. It bridges the gap between detecting a vulnerability and implementing a complex cryptographic migration by providing tailored, engineer-ready playbooks.

---

## 🤖 Dual-Engine Architecture

To ensure high availability and technical depth, QuantumShield utilizes a multi-model orchestration pattern via the **Hugging Face Router**.

### 1. Primary Model: Qwen 2.5 (7B Instruct)
Optimized for logical reasoning and technical CLI precision. It is tasked with generating the primary deep-dive architectural plans.

### 2. Fallback Model: Llama 3.1 (8B Instruct)
A highly stable, general-purpose instructor that takes over if the primary engine encounters rate limits, latency spikes, or JSON parsing errors.

### 3. Safety Net: Expert Static Playbooks
If all AI models are unreachable, the system reverts to **Expert Static Playbooks** written by our team of cryptographers. This ensures the scanner never leaves an analyst without actionable guidance.

---

## 🛠️ The Remediation Pipeline

When a finding is selected, the engine executes the following steps:

1.  **Context Aggregation**: Collects domain metadata, algorithm details (e.g., RSA-2048), and HNDL severity.
2.  **AI Prompting**: Requests an 8-step technical execution plan designed for a Senior DevOps Engineer.
3.  **Snippet Generation**: Generates exact CLI commands for OpenSSL 3.3 and Nginx `ssl_conf_command` blocks for hybrid deployments (e.g., X25519Kyber768).
4.  **Priority Scoring**: Calculates the urgency of the fix using the SRS formula:
    ```text
    Priority Score = HNDL Score × Asset Criticality / 10
    ```

---

## 📖 Anatomy of a Playbook

Each AI-generated playbook contains three critical sections:

### 1. The 8-Step Blueprint
A linear, chronological checklist for migration. It covers everything from inventory tagging and HSM dependency mapping to Revocation and Certificate updates.

### 2. Architectural Deep-Dive
A detailed technical report explaining *why* the specific algorithm is vulnerable to quantum attacks (e.g., explaining Shor's impact on ECC) and the mathematical benefits of the proposed PQC alternative.

### 3. Technical Snippets (CLI/Config)
Drop-in code blocks. Examples include:
- `openssl s_client -groups x25519_kyber768 ...`
- `ssl_conf_command Options Groups x25519_kyber768:x25519:p256`

---

## 🔒 Post-Quantum Recommendations

The engine is biased toward **Crypto-Agility** and **Hybrid Security**, recommending the following as the gold standard:
- **KEM**: ML-KEM-768 (Kyber)
- **Signatures**: ML-DSA-65 (Dilithium)
- **Hybrid Strategy**: NIST FIPS 203/204 compliant wrappers around classical primitives.
