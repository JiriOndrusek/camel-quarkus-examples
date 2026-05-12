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
import java.util.Map;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jboss.logging.Logger;

/**
 * Test resource that generates PQC-ready certificates before tests run.
 * Certificates are generated once per test suite execution and placed in target/certs.
 */
public class CertificateTestResource implements QuarkusTestResourceLifecycleManager {

    private static final Logger LOG = Logger.getLogger(CertificateTestResource.class);

    @Override
    public Map<String, String> start() {
        //        // Remove existing providers to ensure clean state
        //        if (Security.getProvider("DefaultSecureRandom") != null) {
        //            Security.removeProvider("DefaultSecureRandom");
        //        }
        //        if (Security.getProvider("BCJSSE") != null) {
        //            Security.removeProvider("BCJSSE");
        //        }
        //        if (Security.getProvider("BC") != null) {
        //            Security.removeProvider("BC");
        //        }
        //
        // Register DefaultSecureRandomProvider first (position 1)
        // This is needed for BCJSSE to work correctly
        Security.insertProviderAt(new DefaultSecureRandomProvider(), 1);
        LOG.info("Registered DefaultSecureRandomProvider for test client at position 1");
        //
        // Register BC provider for certificate operations (at the end)
        Security.addProvider(new BouncyCastleProvider());
        LOG.info("Registered BouncyCastleProvider for certificate generation");
        //
        //        // Register BCJSSE provider for PQC TLS in test client (position 2)
        //        // This makes it the default JSSE provider
        Security.insertProviderAt(new org.bouncycastle.jsse.provider.BouncyCastleJsseProvider(), 2);
        LOG.info("Registered BouncyCastleJsseProvider for PQC TLS in test client at position 2");
        //
        //        // Remove ECDH from jdk.tls.disabledAlgorithms for compatibility
        //        String disabled = Security.getProperty("jdk.tls.disabledAlgorithms");
        //        if (disabled != null && disabled.contains("ECDH")) {
        //            disabled = disabled.replaceAll(",\\s*ECDH\\b", "");
        //            Security.setProperty("jdk.tls.disabledAlgorithms", disabled);
        //            LOG.info("Removed ECDH from jdk.tls.disabledAlgorithms for test client");
        //        }
        //
        //        // Named groups are now configured via Maven failsafe plugin systemPropertyVariables
        //        // (jdk.tls.namedGroups is set as a JVM argument before any classes are loaded)
        //        String configuredGroups = System.getProperty("jdk.tls.namedGroups", "X25519MLKEM768");
        //        LOG.info("Client-side TLS named groups (from JVM args): " + configuredGroups);

        // Enable SSL debugging for detailed handshake logging
        // Uncomment to see full TLS handshake details including cipher suites
        System.setProperty("javax.net.debug", "ssl:handshake:verbose");

        try {
            LOG.info("Generating PQC-ready certificates for tests...");
            CertificateGenerator.generateServerKeystore();
            CertificateGenerator.generateClientKeystore();
            CertificateGenerator.generateTruststores();
            LOG.info("PQC-ready certificates generated successfully");
        } catch (Exception e) {
            LOG.error("Failed to generate PQC-ready certificates", e);
            throw new RuntimeException("Certificate generation failed", e);
        }
        return Map.of();
    }

    @Override
    public void stop() {
        // Certificates are in target/certs and will be cleaned by mvn clean
    }
}
