---
name: fips-compliance
description: >
  Enforce FIPS 140-2/140-3 compliance for RHEL, OpenShift, and Go workloads.
  Use when building, configuring, reviewing, or auditing systems that require
  FIPS-validated cryptographic modules, RHEL crypto-policy enforcement,
  FIPS-ready Go binaries, or FIPS-mode kernel and cluster configuration.
category: "secure_development"
subcategory: "crypto"
---

# FIPS Compliance

Guidance for enforcing [FIPS 140-2 and 140-3](https://csrc.nist.gov/pubs/fips/140-3/final) across RHEL/RHCOS nodes, OpenShift clusters, Go applications, and container workloads. For algorithm-level guidance, see [`algorithm-selection`](../algorithm-selection/SKILL.md). For TLS enforcement on Kubernetes, see [`tls-compliance`](../tls-compliance/SKILL.md).

## FIPS Mode Enforcement

| Layer | Mechanism | Validation |
|-------|-----------|------------|
| RHCOS/RHEL kernel | `fips=1` boot parameter | `cat /proc/sys/crypto/fips_enabled` returns `1` |
| [RHEL crypto policy](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening) | `update-crypto-policies --set FIPS` | `update-crypto-policies --show` returns `FIPS` |
| [OpenShift cluster](https://docs.openshift.com/container-platform/latest/installing/overview/installing-fips.html) | `fips: true` in `install-config.yaml` | `oc get cm -n openshift-config -o jsonpath='{.items[*].data.install-config}'` |
| [etcd encryption](https://docs.openshift.com/container-platform/latest/security/encrypting-etcd.html) | `aescbc` or `aesgcm` encryption type | See [etcd Encryption at Rest](#etcd-encryption-at-rest) |

> **Critical:** OpenShift FIPS mode must be [enabled at install time](https://docs.openshift.com/container-platform/latest/installing/overview/installing-fips.html) — it cannot be enabled post-deployment. The installer must run from a FIPS-enabled RHEL host using the `openshift-install-fips` binary. Do not use ed25519 SSH keys — use RSA instead.

## FIPS-Approved and Prohibited Algorithms

| Category | Approved | Prohibited |
|----------|----------|------------|
| Symmetric | AES-128, AES-192, AES-256 (GCM, CBC, CCM) | ChaCha20-Poly1305, RC4, Blowfish, DES, 3DES |
| Hashing | SHA-256, SHA-384, SHA-512, SHA-3 | MD5, SHA-1 (for signatures/integrity) |
| Asymmetric | RSA >= 2048, ECDSA (P-256, P-384, P-521) | RSA < 2048, non-NIST curves |
| Key exchange | ECDHE (P-256, P-384), DH >= 2048 | X25519 (not FIPS-validated), static RSA |
| MAC | HMAC-SHA-256, HMAC-SHA-384 | Poly1305 |

> **FIPS and PQC are mutually exclusive today.** [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) (FIPS 203) and [ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) (FIPS 204) are finalized standards, but no RHEL cryptographic module includes them yet. X25519MLKEM768 hybrid key exchange cannot be used on FIPS-enabled clusters.

## RHEL Crypto Policies

[System-wide crypto policies](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening) enforce FIPS constraints across OpenSSL, GnuTLS, NSS, libgcrypt, and the Kernel Crypto API.

```bash
update-crypto-policies --set FIPS
update-crypto-policies --show
```

### Subpolicies

| Subpolicy | Command | Effect |
|-----------|---------|--------|
| `NO-SHA1` | `--set FIPS:NO-SHA1` | Disables SHA-1 in signatures and certificates |
| `NO-ENFORCE-EMS` | `--set FIPS:NO-ENFORCE-EMS` | Relaxes mandatory [TLS Extended Master Secret](#extended-master-secret-ems-enforcement) |
| `OSPP` | `--set FIPS:OSPP` | [Common Criteria](https://www.niap-ccevs.org/) restrictions — RSA/DH >= 3072 bits |
| `NO-CAMELLIA` | `--set FIPS:NO-CAMELLIA` | Removes Camellia ciphers |

Site-specific restrictions can be added via [`.pmod` files](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/creating-and-setting-a-custom-system-wide-cryptographic-policy_security-hardening) in `/etc/crypto-policies/policies/modules/`.

## Go FIPS Builds

### [Red Hat Go Toolset](https://developers.redhat.com/articles/2025/01/23/fips-mode-red-hat-go-toolset) (RHEL)

Routes crypto calls to the FIPS-validated OpenSSL module via CGO — does **not** use Google's BoringCrypto. FIPS detection is automatic via `/proc/sys/crypto/fips_enabled`.

```go
import "github.com/golang-fips/openssl/v2"

func init() { openssl.Init("") }

if openssl.FIPS() {
    // Using FIPS-validated OpenSSL path
}
```

### [Upstream Go 1.24+](https://go.dev/doc/security/fips140) (Native FIPS 140-3, introduced 2025)

Native FIPS 140-3 with [CMVP Certificate #5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247).

| Setting | Options |
|---------|---------|
| `GOFIPS140` (build-time) | `off`, `latest`, `v1.0.0`, `certified`, `inprocess` |
| `GODEBUG=fips140` (runtime) | `off`, `on`, `only` (panics on non-FIPS — non-production) |
| API | [`crypto/fips140.Enabled()`](https://go.dev/doc/security/fips140), `crypto/fips140.Version()` |

### Common Violations

| Violation | Why It Breaks FIPS | Fix |
|-----------|-------------------|-----|
| `CGO_ENABLED=0` | No OpenSSL linkage (Red Hat path) | Set `CGO_ENABLED=1` |
| `-extldflags "-static"` | Prevents `dlopen` of OpenSSL | Use dynamic linking |
| `-tags no_openssl` | Disables OpenSSL integration | Remove the tag |
| Importing [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) | Not FIPS-validated | Use standard `crypto/*` packages |
| `crypto/md5` for integrity | MD5 not FIPS-approved | Use `crypto/sha256` |
| ChaCha20-Poly1305 ciphers | Not FIPS-approved | Use AES-GCM |
| [UBI](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/building_running_and_managing_containers/assembly_types-of-container-images_building-running-and-managing-containers) base image missing OpenSSL | Runtime FIPS detection fails | Use FIPS-enabled UBI with OpenSSL |

### Historical: [CVE-2023-3089](https://access.redhat.com/security/vulnerabilities/RHSB-2023-001)

OCP 4.10–4.12 Go components defaulted to Go's standard crypto instead of OpenSSL, producing ~50% of certificates with non-validated modules. Red Hat added build-time enforcement in OCP 4.13+ that terminates non-compliant builds.

## TLS in FIPS Mode

FIPS mode filters out non-approved ciphers. On OpenShift, the [Ingress Operator](https://docs.openshift.com/container-platform/latest/networking/ingress-operator.html) automatically removes non-compliant ciphers.

**FIPS-approved TLS 1.2:** `TLS_ECDHE_{ECDSA,RSA}_WITH_AES_{128,256}_GCM_SHA{256,384}` (all ECDHE + AES-GCM).

**FIPS-approved TLS 1.3:** `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`. `TLS_CHACHA20_POLY1305_SHA256` is **filtered out** on FIPS clusters.

### [Extended Master Secret (EMS) Enforcement](https://www.redhat.com/en/blog/tls-extended-master-secret-and-fips-rhel)

Starting with RHEL 9.2, [TLS Extended Master Secret](https://datatracker.ietf.org/doc/html/rfc7627) is **mandatory** for all TLS 1.2 connections in FIPS mode (FIPS 140-3 requirement).

**Breaking change:** Legacy clients without EMS or TLS 1.3 support (RHEL 6/7, older Go versions) **cannot connect** to FIPS-enabled RHEL 9.2+ systems over TLS 1.2.

Migration workaround (non-compliant): `update-crypto-policies --set FIPS:NO-ENFORCE-EMS`

## etcd Encryption at Rest

| Type | Algorithm | FIPS Status |
|------|-----------|-------------|
| `aescbc` | AES-CBC, PKCS#7 padding, 32-byte key | Compliant |
| `aesgcm` | AES-GCM | Compliant |
| `identity` | No encryption | **Not compliant** |

```bash
oc get openshiftapiserver -o=jsonpath='{range .items[0].status.conditions[?(@.type=="Encrypted")]}{.reason}{"\n"}{.message}{"\n"}'
oc get kubeapiserver -o=jsonpath='{range .items[0].status.conditions[?(@.type=="Encrypted")]}{.reason}{"\n"}{.message}{"\n"}'
oc get authentication.operator.openshift.io -o=jsonpath='{range .items[0].status.conditions[?(@.type=="Encrypted")]}{.reason}{"\n"}{.message}{"\n"}'
```

Expected output: `EncryptionCompleted`. Keys rotate weekly. Encryption keys are stored in plaintext on API server nodes — this protects backups and offline disk access but not node-level compromise.

## Operator and Workload Considerations

- **cert-manager:** Set `spec.privateKey.algorithm` to RSA (>= 2048) or ECDSA (P-256/P-384). Do not use ed25519.
- **Service mesh:** mTLS must use FIPS-approved ciphers. [PQC key exchange is unavailable](https://www.redhat.com/en/blog/openshift-service-mesh-33-adds-post-quantum-cryptography) on FIPS clusters. Ambient mode supports FIPS 140-2 with TLS 1.2.
- **Container images:** Use [FIPS-enabled UBI base images](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/building_running_and_managing_containers/assembly_types-of-container-images_building-running-and-managing-containers) with OpenSSL present. Containers inherit the host's FIPS mode via `/proc/sys/crypto/fips_enabled`.
- **Terminology:** Use "FIPS validated" (per [NIST](https://csrc.nist.gov/projects/cryptographic-module-validation-program)). "FIPS compliant" and "FIPS certified" are [incorrect terms](https://access.redhat.com/articles/openshift_fips_compliance_faq).

## FIPS Validation Status

Red Hat submits [five cryptographic modules](https://access.redhat.com/articles/3655361) per RHEL release (OpenSSL, Kernel Crypto API, GnuTLS, NSS, libgcrypt) for [NIST CMVP](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules) validation.

| RHEL Version | FIPS Standard | Notes |
|-------------|---------------|-------|
| RHEL 8.x | [FIPS 140-2](https://csrc.nist.gov/pubs/fips/140-2/upd2/final) | Active through September 2026 ([verify status](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules)) |
| RHEL 9.0+ | [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final) | Current standard |
| RHEL 10 | FIPS 140-3 only | Reuses RHEL 9 OpenSSL module |

## Auditing FIPS Compliance

```bash
# Node-level
oc debug node/<node> -- chroot /host cat /proc/sys/crypto/fips_enabled
oc debug node/<node> -- chroot /host update-crypto-policies --show
oc debug node/<node> -- chroot /host grep -o 'fips=[01]' /proc/cmdline

# Cluster-level
oc get ingresscontroller default -n openshift-ingress-operator -o jsonpath='{.spec.tlsSecurityProfile}'

# Go binary (Red Hat toolset)
go tool nm <binary> | grep -i dlopen_openssl
```

## Implementation Checklist

- [ ] Cluster installed with `fips: true` from a [FIPS-enabled RHEL host](https://docs.openshift.com/container-platform/latest/installing/overview/installing-fips.html) using RSA SSH keys
- [ ] All nodes report `fips_enabled = 1` and crypto policy `FIPS`
- [ ] Go binaries built with `CGO_ENABLED=1` / dynamic linking ([Red Hat](https://developers.redhat.com/articles/2025/01/23/fips-mode-red-hat-go-toolset)) or [`GOFIPS140=latest`](https://go.dev/doc/security/fips140) (upstream 1.24+)
- [ ] No static linking, `no_openssl` tags, or `x/crypto` in FIPS-critical paths
- [ ] [etcd encryption](https://docs.openshift.com/container-platform/latest/security/encrypting-etcd.html) enabled (`aescbc` or `aesgcm`)
- [ ] TLS cipher suites restricted to FIPS-approved algorithms
- [ ] [EMS enforcement](https://www.redhat.com/en/blog/tls-extended-master-secret-and-fips-rhel) verified for TLS 1.2 (RHEL 9.2+) or `NO-ENFORCE-EMS` applied with justification
- [ ] cert-manager uses RSA >= 2048 or ECDSA P-256/P-384
- [ ] Container base images are [FIPS-enabled UBI](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/building_running_and_managing_containers/assembly_types-of-container-images_building-running-and-managing-containers) with OpenSSL
- [ ] OCP 4.10–4.12 clusters have applied [CVE-2023-3089](https://access.redhat.com/security/vulnerabilities/RHSB-2023-001) remediation
