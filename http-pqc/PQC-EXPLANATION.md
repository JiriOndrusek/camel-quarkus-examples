# Post-Quantum Cryptography: Visual Explanation

## The Quantum Computer Threat

**Traditional Encryption (RSA/ECC):**
```
┌─────────────────────────────────────────────────────────────┐
│  Current World (Safe)          Future with Quantum Computer │
│                                                               │
│  RSA-2048 encryption           Quantum Computer              │
│  ┌──────────────┐              ┌──────────────┐             │
│  │  Lock (RSA)  │    ──────>   │ Shor's Algo  │             │
│  │ Takes 1000s  │              │ Breaks in    │             │
│  │ of years to  │              │ MINUTES! ⚠️   │             │
│  │ break        │              └──────────────┘             │
│  └──────────────┘                                            │
└─────────────────────────────────────────────────────────────┘
```

**Post-Quantum Cryptography (PQC):**
```
┌─────────────────────────────────────────────────────────────┐
│  PQC Solution                  Even with Quantum Computer    │
│                                                               │
│  Dilithium/ML-DSA              Quantum Computer              │
│  ┌──────────────┐              ┌──────────────┐             │
│  │ Lattice Lock │    ──────>   │ Shor's Algo  │             │
│  │ Based on     │              │ Doesn't work!│             │
│  │ hard math    │              │ Still takes  │             │
│  │ problems     │              │ 1000s years ✓│             │
│  └──────────────┘              └──────────────┘             │
└─────────────────────────────────────────────────────────────┘
```

---

## Three Approaches in Our Implementation

### 1. CURRENT HTTPS (What Most Systems Use Today)

```
┌──────────────┐                                ┌──────────────┐
│   Browser    │                                │    Server    │
│   (Client)   │                                │              │
└──────┬───────┘                                └──────┬───────┘
       │                                               │
       │  1. "Hello, I want HTTPS connection"          │
       ├──────────────────────────────────────────────>│
       │                                               │
       │  2. "Here's my certificate"                   │
       │     ┌─────────────────────────┐               │
       │     │ Certificate:            │               │
       │     │ - Public Key: RSA-2048  │               │
       │     │ - Signature: SHA256+RSA │               │
       │<────│ - Subject: localhost    │───────────────│
       │     │ ⚠️ QUANTUM VULNERABLE   │               │
       │     └─────────────────────────┘               │
       │                                               │
       │  3. Verify RSA signature ✓                    │
       │     (Works today, broken by quantum later)    │
       │                                               │
       │  4. Encrypted communication using RSA         │
       │<─────────────────────────────────────────────>│
       │     ⚠️ Future quantum computer can break this │
       │                                               │
```

**Problem:** When quantum computers arrive, they can:
- Break the RSA encryption
- Forge RSA signatures
- Read all your "encrypted" data

---

### 2. OUR IMPLEMENTATION: Programmatic PQC (Java 17 Limitation)

Because Java 17 doesn't support PQC in TLS, we demonstrate PQC **inside** the application:

```
┌──────────────┐                                ┌──────────────┐
│   Browser    │                                │    Server    │
│   (curl)     │                                │  (Quarkus)   │
└──────┬───────┘                                └──────┬───────┘
       │                                               │
       │  LAYER 1: HTTPS (Still uses RSA - Java 17)    │
       │  ════════════════════════════════════════     │
       │  1. TLS Handshake with RSA certificate        │
       ├──────────────────────────────────────────────>│
       │     ┌─────────────────────────┐               │
       │     │ TLS Certificate:        │               │
       │     │ - RSA-2048 (classical)  │               │
       │<────│ ⚠️ Quantum vulnerable   │───────────────│
       │     └─────────────────────────┘               │
       │                                               │
       │  2. Encrypted tunnel established              │
       │<═════════════════════════════════════════════>│
       │                                               │
       │  LAYER 2: PQC at Application Level            │
       │  ════════════════════════════════════════     │
       │  3. GET /pqc/sign                             │
       ├──────────────────────────────────────────────>│
       │                                               │
       │                                    ┌──────────┴───────────┐
       │                                    │ PqcSignatureService  │
       │                                    │ - Generate Dilithium3│
       │                                    │   keypair            │
       │                                    │ - Sign message       │
       │                                    │ - Verify signature   │
       │                                    │ ✓ QUANTUM SAFE       │
       │                                    └──────────┬───────────┘
       │  4. Returns PQC signature demo                │
       │     "Dilithium3 signature: [bytes]"           │
       │     "Verification: ✓ VALID"                   │
       │<──────────────────────────────────────────────│
       │                                               │
       │  5. GET /pqc/kem                              │
       ├──────────────────────────────────────────────>│
       │                                               │
       │                                    ┌──────────┴─────────┐
       │                                    │   PqcKemService    │
       │                                    │ - NTRU keypair     │
       │                                    │ - Key encapsulation│
       │                                    │ ✓ QUANTUM SAFE     │
       │                                    └──────────┬─────────┘
       │  6. Returns KEM demo                          │
       │<──────────────────────────────────────────────│
       │                                               │
```

**Current State:**
- ✅ **Application uses real PQC algorithms** (Dilithium3, NTRU)
- ✅ **Demonstrates quantum-safe signatures and key exchange**
- ⚠️ **But the HTTPS tunnel itself is still RSA** (Java 17 limitation)
- ℹ️ **Think of it as:** A quantum-safe vault (PQC app) inside a regular house (RSA TLS)

---

### 3. CHIMERA HYBRID CERTIFICATES (Our New Implementation!)

This is the **best approach** for transitioning to PQC:

```
┌──────────────┐                                ┌──────────────┐
│   Browser    │                                │    Server    │
│   (Client)   │                                │              │
└──────┬───────┘                                └──────┬───────┘
       │                                               │
       │  1. "Hello, I want HTTPS connection"          │
       ├──────────────────────────────────────────────>│
       │                                               │
       │  2. "Here's my HYBRID certificate"            │
       │     ┌─────────────────────────────────────┐   │
       │     │  Chimera Hybrid Certificate:        │   │
       │     │  ────────────────────────────────   │   │
       │     │  PRIMARY (Classical):               │   │
       │     │  - Public Key: RSA-2048             │   │
       │     │  - Signature: SHA256withRSA         │   │
       │     │  ✓ Works with old systems           │   │
       │     │                                     │   │
       │     │  ALTERNATIVE (PQC) - Extensions:    │   │
       │<────│  - altPublicKey: Dilithium3         │───│
       │     │  - altSignature: Dilithium3         │   │
       │     │  ✓ QUANTUM SAFE                     │   │
       │     │                                     │   │
       │     │  BOTH signatures present!           │   │
       │     └─────────────────────────────────────┘   │
       │                                               │
       │  3. Verify RSA signature ✓                    │
       │     (Works with old browsers)                 │
       │                                               │
       │  4. Verify Dilithium3 signature ✓             │
       │     (PQC-aware clients check this too)        │
       │                                               │
       │  5. Encrypted communication                   │
       │<─────────────────────────────────────────────>│
       │     ✓ Protected by BOTH classical & PQC       │
       │                                               │
```

**How Chimera Works:**

```
┌─────────────────────────────────────────────────────────────┐
│              CHIMERA HYBRID CERTIFICATE                     │
│                                                             │
│  ┌────────────────────┐      ┌────────────────────┐         │
│  │   PRIMARY LAYER    │      │ ALTERNATIVE LAYER  │         │
│  │   (Classical RSA)  │      │   (PQC Dilithium)  │         │
│  └─────────┬──────────┘      └─────────┬──────────┘         │
│            │                           │                    │
│            │  Subject: CN=localhost    │                    │
│            │  Issuer: CN=PQC Hybrid CA │                    │
│            │  Serial: 1234567890       │                    │
│            │                           │                    │
│  ┌─────────▼──────────┐      ┌─────────▼──────────┐         │
│  │ RSA-2048           │      │ Extension OID      │         │
│  │ Public Key         │      │ 2.5.29.72:         │         │
│  │ (Standard field)   │      │ Dilithium3 Public  │         │
│  └────────────────────┘      │ Key                │         │
│                              └────────────────────┘         │
│  ┌────────────────────┐      ┌────────────────────┐         │
│  │ SHA256withRSA      │      │ Extension OID      │         │
│  │ Signature          │      │ 2.5.29.74:         │         │
│  │ [RSA signature     │      │ Dilithium3         │         │
│  │  bytes]            │      │ Signature bytes    │         │
│  └────────────────────┘      └────────────────────┘         │
│                                                             │
│  Verification: BOTH signatures must be valid!               │
│  - Old systems: Check RSA only ✓                            │
│  - PQC systems: Check RSA ✓ AND Dilithium ✓                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Certificate Comparison

### Traditional Certificate (RSA only)
```
┌─────────────────────────────────┐
│ X.509 Certificate               │
├─────────────────────────────────┤
│ Version: 3                      │
│ Serial: 0x123456                │
│ Issuer: CN=My CA                │
│ Subject: CN=localhost           │
│ ┌─────────────────────────────┐ │
│ │ Public Key:                 │ │
│ │   Algorithm: RSA            │ │
│ │   Size: 2048 bits           │ │
│ │   Key: [MIIBIjANBg...]      │ │
│ └─────────────────────────────┘ │
│ ┌─────────────────────────────┐ │
│ │ Signature:                  │ │
│ │   Algorithm: SHA256withRSA  │ │
│ │   Value: [3045022100...]    │ │
│ └─────────────────────────────┘ │
│                                 │
│ ⚠️ QUANTUM VULNERABLE           │
└─────────────────────────────────┘
```

### Chimera Hybrid Certificate (RSA + Dilithium3)
```
┌─────────────────────────────────────────────────────┐
│ X.509 Certificate (Chimera Format)                  │
├─────────────────────────────────────────────────────┤
│ Version: 3                                          │
│ Serial: 0x123456                                    │
│ Issuer: CN=PQC Hybrid CA                            │
│ Subject: CN=localhost                               │
│ ┌─────────────────────────────┐                     │
│ │ Public Key (PRIMARY):       │                     │
│ │   Algorithm: RSA            │ ✓ Classical         │
│ │   Size: 2048 bits           │                     │
│ │   Key: [MIIBIjANBg...]      │                     │
│ └─────────────────────────────┘                     │
│ ┌─────────────────────────────┐                     │
│ │ Extensions:                 │                     │
│ │ ┌─────────────────────────┐ │                     │
│ │ │ OID 2.5.29.72:          │ │                     │
│ │ │ altSubjectPublicKeyInfo │ │                     │
│ │ │   Algorithm: Dilithium3 │ │ ✓ Post-Quantum      │
│ │ │   Key: [3082071E...]    │ │                     │
│ │ │   Size: 1976 bytes      │ │                     │
│ │ └─────────────────────────┘ │                     │
│ │ ┌─────────────────────────┐ │                     │
│ │ │ OID 2.5.29.73:          │ │                     │
│ │ │ altSignatureAlgorithm   │ │                     │
│ │ │   Algorithm: Dilithium3 │ │                     │
│ │ └─────────────────────────┘ │                     │
│ │ ┌─────────────────────────┐ │                     │
│ │ │ OID 2.5.29.74:          │ │                     │
│ │ │ altSignatureValue       │ │                     │
│ │ │   Signature: [D1L1...]  │ │ ✓ Post-Quantum      │
│ │ │   Size: 3309 bytes      │ │                     │
│ │ └─────────────────────────┘ │                     │
│ └─────────────────────────────┘                     │
│ ┌─────────────────────────────┐                     │
│ │ Signature (PRIMARY):        │                     │
│ │   Algorithm: SHA256withRSA  │ ✓ Classical         │
│ │   Value: [3045022100...]    │                     │
│ └─────────────────────────────┘                     │
│                                                     │
│ ✓ HYBRID: Protected against classical AND quantum!  │
└─────────────────────────────────────────────────────┘
```

---

## Our Implementation: Three Demonstrations

```
┌────────────────────────────────────────────────────────────────┐
│              HTTP PQC Example - Three Approaches               │
└────────────────────────────────────────────────────────────────┘

1️⃣  PURE PQC SIGNATURES (Dilithium3)
    ───────────────────────────────
    Endpoint: https://localhost:8443/pqc/sign
    
    ┌─────────────┐      ┌─────────────────┐      ┌──────────┐
    │   Client    │─────>│ PqcSignature    │─────>│ Message  │
    │   Request   │      │ Service         │      │ "Hello"  │
    └─────────────┘      └─────────────────┘      └──────────┘
                                │
                                ▼
                         ┌──────────────┐
                         │ Dilithium3   │
                         │ KeyPair      │
                         └──────┬───────┘
                                │
                   ┌────────────┴───────────┐
                   ▼                        ▼
            ┌──────────┐            ┌──────────┐
            │  Sign    │            │  Verify  │
            │ Message  │            │Signature │
            └──────────┘            └──────────┘
                   │                        │
                   └────────────┬───────────┘
                                ▼
                         Result: ✓ VALID
                         (Quantum-safe!)


2️⃣  KEY ENCAPSULATION (NTRU)
    ─────────────────────────
    Endpoint: https://localhost:8443/pqc/kem
    
    ┌─────────────┐      ┌─────────────────┐      ┌──────────┐
    │   Client    │─────>│  PqcKem         │─────>│ Generate │
    │   Request   │      │  Service        │      │ Keys     │
    └─────────────┘      └─────────────────┘      └──────────┘
                                │
                                ▼
                         ┌──────────────┐
                         │ NTRU KeyPair │
                         │ Public: 727B │
                         │Private: 965B │
                         └──────┬───────┘
                                │
                                ▼
                         Demonstrates how to
                         establish shared secret
                         (Quantum-safe!)


3️⃣  HYBRID CERTIFICATES (Chimera)
    ────────────────────────────────
    Endpoint: https://localhost:8443/pqc/hybrid
    
    ┌─────────────┐      ┌─────────────────────┐
    │   Client    │─────>│ HybridCertificate   │
    │   Request   │      │ Service             │
    └─────────────┘      └─────────┬───────────┘
                                   │
                         ┌─────────┴─────────┐
                         │ Generate 2 Keypairs│
                         └─────────┬─────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
            ┌───────────────┐            ┌────────────────┐
            │ RSA-2048      │            │ Dilithium3     │
            │ Classical     │            │ Post-Quantum   │
            └───────┬───────┘            └────────┬───────┘
                    │                             │
                    └──────────────┬──────────────┘
                                   ▼
                         ┌──────────────────┐
                         │ Build X.509 Cert │
                         │ with Extensions  │
                         └────────┬─────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │ Verify BOTH signatures:   │
                    │  1. RSA ✓                │
                    │  2. Dilithium3 ✓         │
                    └───────────────────────────┘
                    
                    Result: Dual protection!
                    (Works now + Quantum-safe!)
```

---

## Why Chimera is the Best Migration Path

```
┌─────────────────────────────────────────────────────────────┐
│                 MIGRATION TIMELINE                          │
└─────────────────────────────────────────────────────────────┘

TODAY (2026)                    FUTURE (Quantum Computers)
════════════                    ══════════════════════════

Old Browser:                    PQC-Aware Browser:
┌────────────┐                  ┌────────────┐
│ Only knows │                  │ Checks RSA │
│ RSA        │                  │ AND        │
└──────┬─────┘                  │ Dilithium  │
       │                        └──────┬─────┘
       │  Chimera                      │
       │  Certificate                  │
       ▼                               ▼
┌──────────────┐              ┌──────────────┐
│ Verifies RSA │              │ Verifies RSA │
│ signature ✓  │              │ signature ✓  │
│              │              │              │
│ Ignores      │              │ ALSO checks  │
│ Dilithium    │              │ Dilithium ✓  │
│ (unknown     │              │              │
│ extension)   │              │ Double       │
│              │              │ protected!   │
│ ✓ Works!     │              │ ✓ Quantum    │
│              │              │   safe!      │
└──────────────┘              └──────────────┘

ADVANTAGE: One certificate works for everyone!
```

---

## Real-World Example: Accessing the Server

### Step-by-Step with curl:

```bash
# 1. Access the signature endpoint
$ curl -k https://localhost:8443/pqc/sign

ML-DSA-65 Digital Signature Demonstration
==========================================

Algorithm: Dilithium3 (FIPS 204)
Message: "Hello, Post-Quantum World!"
Signature (first 64 chars): rhWT+qEJSzKcslV4G67+evnVzAucZsLY...
Signature Length: 4412 characters (base64)
Verification: ✓ VALID

Status: Post-quantum signature successfully generated and verified!
```

**What just happened:**
```
Your Computer         HTTPS Tunnel (RSA)         Server
    │  ──────────────────────────────────────>   │
    │         curl request                       │
    │                                            │
    │                                            ▼
    │                                    ┌───────────────┐
    │                                    │Generate       │
    │                                    │Dilithium3 keys│
    │                                    └───────┬───────┘
    │                                            │
    │                                    ┌───────▼───────┐
    │                                    │Sign message   │
    │                                    │with Dilithium │
    │                                    └───────┬───────┘
    │                                            │
    │                                    ┌───────▼───────┐
    │                                    │Verify         │
    │                                    │signature      │
    │                                    └───────┬───────┘
    │  <──────────────────────────────────────   │
    │         Response with demo result          │
```

---

## Summary: What We've Built

| Component | What It Does | Quantum Safe? |
|-----------|-------------|---------------|
| **HTTPS Transport** | Encrypts connection (Java 17 limitation) | ⚠️ No (RSA) |
| **PqcSignatureService** | Dilithium3 signatures | ✅ Yes |
| **PqcKemService** | NTRU key exchange | ✅ Yes |
| **HybridCertificateService** | Chimera dual certificates | ✅ Yes (Dilithium layer) |

**Think of it like this:**
- The **highway** (HTTPS/TLS) is still built with old materials (RSA)
- But the **cars** (application data) use quantum-safe locks (Dilithium, NTRU)
- The **Chimera certificate** is like a dual-lock system: one lock works today, the other protects against future quantum attacks

**When Java 21+ becomes standard:**
- The highway itself can be upgraded to PQC
- Chimera certificates will work perfectly with full PQC TLS
- Zero code changes needed - we're already PQC-ready!
