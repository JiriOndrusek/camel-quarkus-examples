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

import java.security.SecureRandom;
import java.security.Security;

import io.quarkus.arc.DefaultBean;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

@DefaultBean
@ApplicationScoped
public class SecurityConfiguration {

    private static final Logger LOG = Logger.getLogger(SecurityConfiguration.class);

    // Static initializer to ensure SecureRandom is available BEFORE Quarkus/Vertx
    // initializes SSL context. This is critical for native mode where BouncyCastle
    // JSSE needs SecureRandom during SSL context creation.
    //
    // Configure securerandom.source to use /dev/urandom for faster initialization
    // in containerized environments while maintaining sufficient entropy.
    static {
        try {
            // Set SecureRandom source before any initialization
            // Use file:/dev/urandom instead of file:/dev/random to avoid blocking
            Security.setProperty("securerandom.source", "file:/dev/urandom");

            // Pre-initialize SecureRandom to ensure it's available for BouncyCastle JSSE
            SecureRandom sr = new SecureRandom();
            sr.nextBytes(new byte[1]);
            LOG.info("Static initialization: SecureRandom pre-initialized with /dev/urandom source");
        } catch (Exception e) {
            LOG.error("Failed to initialize SecureRandom in static block", e);
            throw new ExceptionInInitializerError(e);
        }
    }

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

        // Remove existing BC providers to ensure clean state for each test
        if (Security.getProvider("BCJSSE") != null) {
            Security.removeProvider("BCJSSE");
            LOG.info("Removed existing BouncyCastleJsseProvider");
        }
        if (Security.getProvider("BC") != null) {
            Security.removeProvider("BC");
            LOG.info("Removed existing BouncyCastleProvider");
        }

        // Register BC at the end (low priority) so BCJSSE can use it
        // for key conversion, while JDK's SUN/SunJCE remain the preferred
        // providers for PKCS12 KeyStore and PBE algorithms.
        Security.addProvider(new BouncyCastleProvider());
        LOG.info("Registered BouncyCastleProvider at end of provider list");

        // Register BCJSSE at position 1 for TLS.
        // BCJSSE will find BC from the global provider list.
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 1);
        LOG.info("Registered BouncyCastleJsseProvider at position 1");

        // Configure JSSE to enable PQC hybrid key exchange algorithms
        // X25519MLKEM768 combines classical X25519 ECDH with quantum-resistant ML-KEM-768
        // Read from configuration (supports profile-specific overrides for testing)
        String configuredGroups = ConfigProvider.getConfig()
                .getOptionalValue("pqc.tls.named.groups", String.class)
                .orElse("X25519MLKEM768");
        System.setProperty("jdk.tls.namedGroups", configuredGroups);
        LOG.info("Configured TLS named groups for PQC: " + configuredGroups);

        LOG.info("BouncyCastle JSSE provider registered for PQC TLS support");
        LOG.info("Provider: " + Security.getProvider("BCJSSE").getInfo());
    }
}
