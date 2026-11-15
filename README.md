# Vault Broker Core | Go Secrets Management, Dynamic Credentials and Key Rotation

Vault Broker Core is a Go project for coordinating secrets and short-lived credentials across services and infrastructure. Its documented capabilities include envelope encryption, Shamir secret sharing, expiring credential leases, rotation workflows, and cloud/database provider integrations. It is relevant to platform teams researching secrets orchestration and zero-trust credential lifecycles; review the implementation and threat model before storing production secrets.

### *Cloud-Agnostic Secret Orchestration & Ephemeral Credential Broker*

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=2,12,20,28,34&height=220&section=header&text=Vault%20Broker%20Core&fontSize=52&fontAlignY=38&desc=Zero-Trust%20Dynamic%20Credential%20Minting%20%7C%20Envelope%20Encryption%20%7C%20Shamir%20SSS&descAlignY=58&descSize=18" width="100%"/>
</p>

<p align="center">
  <a href="https://github.com/ER-brocode/vault-broker-core/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/ER-brocode/vault-broker-core/ci.yml?branch=main&style=for-the-badge&logo=githubactions&logoColor=white&label=CI%20Verification" alt="CI Status" />
  </a>
  <a href="https://golang.org">
    <img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go Version" />
  </a>
  <a href="https://spiffe.io">
    <img src="https://img.shields.io/badge/Zero--Trust-SPIFFE%2FSPIRE-FF5722?style=for-the-badge&logo=shield&logoColor=white" alt="SPIFFE" />
  </a>
  <a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">
    <img src="https://img.shields.io/badge/Encryption-AES--256--GCM-2E7D32?style=for-the-badge&logo=lock&logoColor=white" alt="AES-256" />
  </a>
</p>

---

## 🚀 Overview

`vault-broker-core` is an enterprise-grade, cloud-agnostic secret orchestration and ephemeral credential brokering engine written in Go. It eliminates standing privileges and hardcoded static secrets across multi-cloud environments by minting short-lived, tightly-scoped access tokens on-demand, strictly linked to cryptographic workload identities (SPIFFE IDs).

```
                      [ Workload / Microservice ]
                                  │
                  (1) Present Cryptographic Identity (SPIFFE ID)
                                  ▼
                    ┌───────────────────────────┐
                    │     vault-broker-core     │
                    │                           │
                    │ ✦ AES-256-GCM Envelope   │
                    │ ✦ Shamir Secret Sharing   │
                    │ ✦ Dynamic Lease Engine    │
                    │ ✦ Auto-Rotation Daemon    │
                    └─────────────┬─────────────┘
                                  │
     ┌────────────────────────────┼────────────────────────────┐
     ▼                            ▼                            ▼
[ AWS IAM STS ]           [ GCP IAM Service ]          [ Relational DBs ]
(Temporary Session)       (Short-lived OAuth2)         (Dynamic Roles/Users)
```

---

## 💎 Core Architecture & Capabilities

### 1. 🛡️ Cryptographic Envelope Encryption (`pkg/vault/envelope.go`)
- **AES-256-GCM Authenticated Encryption**: Plaintext secrets are encrypted with a single-use ephemeral Data Encryption Key (DEK).
- **HKDF Key Derivation**: Sub-keys for wrapping DEKs are deterministically derived via HMAC-based Extract-and-Expand Key Derivation (`RFC 5869`).
- **Additional Authenticated Data (AAD)**: Context-bound tamper-proofing guaranteeing payload integrity.

### 2. 🧩 Shamir's Secret Sharing (`pkg/vault/shamir.go`)
- **$(k, n)$ Threshold Splitting over $\mathbb{GF}(p)$**: Splits 256-bit root master keys into $n$ separate cryptographic shares.
- Reconstructable only when at least $k$ threshold shares are presented using polynomial Lagrange interpolation over large prime Galois fields ($2^{256} - 189$).

### 3. ⏳ Ephemeral Dynamic Lease Manager (`pkg/lease/manager.go`)
- **Deterministic TTL Enforcement**: Every minted credential receives a strict Time-To-Live (TTL) with maximum bounded renewal caps.
- **Background Active Reaper**: Concurrently inspects expired credentials and triggers provider-level revocation callbacks.
- **Graceful Cleanups**: Automatically drops dynamic database users and revokes cloud STS sessions upon expiration or explicit deletion.

### 4. 🔄 Auto-Rotation Daemon (`pkg/lease/rotator.go`)
- Zero-downtime automated credential rotation prior to expiration window thresholds.
- Non-blocking concurrent dispatching with deduplication to prevent double-rotation race conditions.

### 5. 🌐 Cloud & Database Providers (`pkg/provider/`)
- **AWS IAM**: Dynamic STS AssumeRole with Web Identity session broker.
- **GCP Service Account**: Ephemeral OAuth2 access token generator with custom permission scoping.
- **Database (PostgreSQL / MySQL)**: Auto-provisioning of ephemeral database users with custom roles and auto-drop triggers.

---

## 📁 Repository Directory Structure

```text
vault-broker-core/
├── .github/
│   └── workflows/
│       └── ci.yml                 # GitHub Actions automated test & verification suite
├── pkg/
│   ├── vault/
│   │   ├── envelope.go            # AES-256-GCM envelope encryption & HKDF key derivation
│   │   └── shamir.go              # Shamir Secret Sharing (k, n) polynomial scheme over GF(p)
│   ├── lease/
│   │   ├── manager.go             # Dynamic lease lifecycle engine & automatic reaper
│   │   └── rotator.go             # Zero-downtime auto-rotation background daemon
│   └── provider/
│       ├── provider.go            # Common dynamic credential interfaces & request types
│       ├── aws.go                 # AWS IAM STS ephemeral session broker
│       ├── gcp.go                 # Google Cloud Service Account OAuth2 token broker
│       └── database.go            # Ephemeral PostgreSQL / MySQL dynamic user manager
├── tests/
│   ├── envelope_test.go           # Envelope encryption & Shamir split/combine unit tests
│   └── lease_test.go              # Lease lifecycle, expiration, auto-rotation & provider tests
├── go.mod                         # Go module definitions & dependencies
└── README.md                      # Architecture documentation & animated visual manual
```

---

## ⚡ Quickstart & Testing

### Prerequisites
- Go 1.22 or higher

### Running Tests
Execute the comprehensive automated test suite with race detection and code coverage:

```bash
# Run all unit and integration tests
go test -v -race -cover ./...
```

---

## 🔒 Security Guarantee
- No static secrets stored at rest in plaintext.
- High-entropy cryptographically secure pseudorandom number generators (`crypto/rand`).
- Ephemeral credentials default to the principle of least privilege (PoLP).

---

<p align="center">
  <b>Authored by koushik4475 for ER-brocode</b><br/>
  <i>Engineered for zero-trust cloud-native infrastructures.</i>
</p>
