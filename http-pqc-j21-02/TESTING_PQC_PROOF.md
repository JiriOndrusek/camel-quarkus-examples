# Proving X25519MLKEM768 is Actually Used

## The Challenge

The server is configured with fallback algorithms for compatibility:
```
jdk.tls.namedGroups = X25519MLKEM768,secp256r1,secp384r1,secp521r1
```

This means we can't prove with 100% certainty which algorithm is actually negotiated in automated tests, because the server could theoretically fall back to classical algorithms.

## What the Automated Tests DO Prove

Our current test suite provides **strong logical evidence**:

###  HttpPqcTest
- ✓ BCJSSE provider is at Security position 1 (handles ALL TLS)
- ✓ Socket implementation is BouncyCastle (not standard JDK)
- ✓ X25519MLKEM768 is configured with highest priority
- ✓ TLS 1.3 handshake succeeds
- ✓ Comparison shows BCJSSE vs SunJSSE use different implementations

### SslDebugCaptureTest  
- ✓ Session introspection confirms BouncyCastle implementation
- ✓ Logical chain: BCJSSE is ONLY provider with X25519MLKEM768 support on JDK 21
- ✓ If BCJSSE handles connection and X25519MLKEM768 is first, it WILL be negotiated

### Logical Conclusion
Since:
1. BCJSSE is the ONLY provider handling TLS connections (position 1)
2. BCJSSE is the ONLY provider supporting X25519MLKEM768 on JDK 21  
3. X25519MLKEM768 is configured with highest priority
4. Both client and server support it

Then **X25519MLKEM768 MUST be negotiated** (TLS spec: first mutually supported algorithm wins)

## Manual Procedure for Definitive Proof

To get **absolute proof** that X25519MLKEM768 is used, configure the server with NO fallback:

### Step 1: Modify SecurityConfiguration Temporarily

Edit `src/main/java/org/acme/http/pqc/SecurityConfiguration.java`:

```java
// Change this line (around line 57):
System.setProperty("jdk.tls.namedGroups",
    "X25519MLKEM768,secp256r1,secp384r1,secp521r1");

// To:
System.setProperty("jdk.tls.namedGroups",
    "X25519MLKEM768");  // ONLY PQC, no fallback
```

### Step 2: Start the Server

```bash
mvn clean compile quarkus:dev
```

Server should start successfully with PQC-only configuration.

### Step 3: Test with BCJSSE Client (Should Succeed)

```bash
# In another terminal
cd src/test/resources
javac -cp "../../../target/test-classes:../../../target/classes" TestBCJSSE.java
java -cp ".:../../../target/test-classes:../../../target/classes:~/.m2/repository/org/bouncycastle/bctls-jdk18on/1.84/bctls-jdk18on-1.84.jar" TestBCJSSE

# Expected: Connection succeeds
```

### Step 4: Test with Standard JDK Client (Should Fail)

```bash
# Try with curl (uses standard JDK TLS)
curl -v --tlsv1.3 \
  --cert target/certs/client-keystore.p12:changeit \
  --cert-type P12 \
  https://localhost:8443/api/data

# Expected: Handshake failure (no common algorithms)
```

### Step 5: Verify with OpenSSL

```bash
# OpenSSL doesn't support X25519MLKEM768 yet, so this should fail:
openssl s_client -connect localhost:8443 \
  -cert target/certs/client-keystore.p12 \
  -certform P12

# Expected: Handshake failure
```

### Result

If:
- ✓ BCJSSE client **succeeds**
- ✗ Standard JDK client **fails**  
- ✗ OpenSSL **fails**

Then **X25519MLKEM768 is definitively being used**.

There's no other algorithm available for fallback.

## Network-Level Proof (Ultimate Verification)

For absolute certainty, capture the actual TLS handshake:

```bash
# Terminal 1: Start packet capture
sudo tcpdump -i lo -w pqc-handshake.pcap port 8443

# Terminal 2: Start server (with X25519MLKEM768 only)
mvn quarkus:dev

# Terminal 3: Make a connection
# (use BCJSSE client from Step 3 above)

# Stop capture and analyze with Wireshark
wireshark pqc-handshake.pcap
```

In Wireshark, filter for `tls.handshake`:
1. Look at **ClientHello** → Supported Groups extension
2. Look at **ServerKeyExchange** → Named Group field  
3. If you see `x25519mlkem768 (0x11ec)` → **DEFINITIVE PROOF**

## Why Automated Testing Can't Provide Absolute Proof

1. **Server has fallback**: `secp256r1,secp384r1,secp521r1` for compatibility
2. **Same JVM**: Test client and server share system properties  
3. **Timing**: Can't reconfigure server mid-test without restart
4. **No API**: BouncyCastle doesn't expose negotiated group via public API

The manual procedure above eliminates these constraints.

## Conclusion

**For Development/CI**: Current automated tests provide **strong logical proof**

**For Demonstration/Audit**: Use manual procedure with X25519MLKEM768-only configuration

**For Publication/Research**: Use network capture showing actual handshake bytes

The theoretical possibility that BCJSSE would skip X25519MLKEM768 (despite it being first and mutually supported) contradicts the TLS 1.3 specification and BouncyCastle's documented behavior.
