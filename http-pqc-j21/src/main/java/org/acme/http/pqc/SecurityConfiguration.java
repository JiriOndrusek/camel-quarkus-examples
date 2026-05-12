/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.acme.http.pqc;

import java.security.Security;

import io.quarkus.arc.DefaultBean;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.jboss.logging.Logger;

@DefaultBean
@ApplicationScoped
public class SecurityConfiguration {

    private static final Logger LOG = Logger.getLogger(SecurityConfiguration.class);

    //    // Static initializer to ensure SecureRandom is available BEFORE Quarkus/Vertx
    //    // initializes SSL context. This is critical for native mode where BouncyCastle
    //    // JSSE needs SecureRandom during SSL context creation.
    //    //
    //    // Configure securerandom.source to use /dev/urandom for faster initialization
    //    // in containerized environments while maintaining sufficient entropy.
    //    static {
    //        try {
    //            // Set SecureRandom source before any initialization
    //            // Use file:/dev/urandom instead of file:/dev/random to avoid blocking
    //            Security.setProperty("securerandom.source", "file:/dev/urandom");
    //
    //            // Pre-initialize SecureRandom to ensure it's available for BouncyCastle JSSE
    //            SecureRandom sr = new SecureRandom();
    //            sr.nextBytes(new byte[1]);
    //            LOG.info("Static initialization: SecureRandom pre-initialized with /dev/urandom source");
    //        } catch (Exception e) {
    //            LOG.error("Failed to initialize SecureRandom in static block", e);
    //            throw new ExceptionInInitializerError(e);
    //        }
    //    }
    //
    //    /**
    //     * Check if a named group ID is known to work.
    //     * Used by reflection-based workaround to force-enable groups in native mode.
    //     */
    //    private static boolean isKnownWorkingGroup(int namedGroup) {
    //        switch (namedGroup) {
    //        case 0x001D: // x25519
    //        case 0x001E: // x448
    //        case 0x0017: // secp256r1
    //        case 0x0018: // secp384r1
    //        case 0x0019: // secp521r1
    //        case 0x0100: // ffdhe2048
    //        case 0x0101: // ffdhe3072
    //        case 0x0102: // ffdhe4096
    //        case 0x0103: // ffdhe6144
    //        case 0x0104: // ffdhe8192
    //        case 0x0200: // MLKEM512
    //        case 0x0201: // MLKEM768
    //        case 0x0202: // MLKEM1024
    //        case 0x11EB: // SecP256r1MLKEM768
    //        case 0x11EC: // X25519MLKEM768
    //        case 0x11ED: // SecP384r1MLKEM1024
    //        case 0x11EE: // curveSM2MLKEM768
    //            return true;
    //        default:
    //            return false;
    //        }
    //    }

    void onStart(@Observes StartupEvent ev) {
        // Remove ECDH from jdk.tls.disabledAlgorithms.
        // JDK 21 disables raw "ECDH" which BCJSSE interprets broadly,
        // preventing EC credentials from being used in TLS handshakes.
        String disabled = Security.getProperty("jdk.tls.disabledAlgorithms");
        if (disabled != null) {
            disabled = disabled.replaceAll(",\\s*ECDH\\b", "");
            Security.setProperty("jdk.tls.disabledAlgorithms", disabled);
            LOG.info("Removed ECDH from jdk.tls.disabledAlgorithms for BouncyCastle compatibility");
        }

        // Remove existing providers to ensure clean state for each test
        if (Security.getProvider("DefaultSecureRandom") != null) {
            Security.removeProvider("DefaultSecureRandom");
            LOG.info("Removed existing DefaultSecureRandomProvider");
        }
        if (Security.getProvider("BCJSSE") != null) {
            Security.removeProvider("BCJSSE");
            LOG.info("Removed existing BouncyCastleJsseProvider");
        }
        if (Security.getProvider("BC") != null) {
            Security.removeProvider("BC");
            LOG.info("Removed existing BouncyCastleProvider");
        }

        // CRITICAL for native mode: Register custom provider that provides "DEFAULT" SecureRandom.
        // BouncyCastle JSSE calls SecureRandom.getInstance("DEFAULT") during SSL context
        // initialization, but in GraalVM native images no provider registers this algorithm.
        // Register at high priority so it's found before other providers.
        Security.insertProviderAt(new DefaultSecureRandomProvider(), 1);
        LOG.info("Registered DefaultSecureRandomProvider for DEFAULT SecureRandom algorithm");

        // Register BC at the end (low priority) so BCJSSE can use it
        // for key conversion, while JDK's SUN/SunJCE remain the preferred
        // providers for PKCS12 KeyStore and PBE algorithms.
        Security.addProvider(new BouncyCastleProvider());
        LOG.info("Registered BouncyCastleProvider at end of provider list");

        // Register BCJSSE at position 2 for TLS (after DefaultSecureRandom provider).
        // BCJSSE will now be able to call SecureRandom.getInstance("DEFAULT") successfully.
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);
        LOG.info("Registered BouncyCastleJsseProvider at position 2");

    }
}
