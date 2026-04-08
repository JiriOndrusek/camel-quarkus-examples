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

import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;

import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
public class SecurityConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(SecurityConfiguration.class);

    void onStart(@Observes StartupEvent ev) {
        // Register BouncyCastle as the first provider to ensure PQC algorithms are available
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        LOG.info("BouncyCastle provider registered at position 1 for PQC support");

        // Verify BouncyCastle is properly registered
        Provider bcProvider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (bcProvider != null) {
            LOG.info("BouncyCastle provider confirmed: {} version {}",
                    bcProvider.getName(), bcProvider.getVersion());
        } else {
            LOG.error("BouncyCastle provider not found!");
            throw new RuntimeException("BouncyCastle provider registration failed");
        }

        // Verify PQC algorithms are available
        verifyPqcAlgorithms();

        // Generate hybrid PQC keystores if they don't exist
        generateKeystoresIfNeeded();
    }

    private void verifyPqcAlgorithms() {
        try {
            // Test Dilithium3 (ML-DSA-65 equivalent, FIPS 204 Level 3) availability
            // BouncyCastle 1.78.1 uses legacy names; ML-DSA names require BC 1.79+
            Signature.getInstance("Dilithium3", "BC");
            KeyPairGenerator.getInstance("Dilithium3", "BC");
            LOG.info("✓ Dilithium3 (ML-DSA-65 / FIPS 204) algorithm available");
        } catch (Exception e) {
            LOG.error("✗ Dilithium3 algorithm NOT available: {}", e.getMessage());
            throw new RuntimeException("Dilithium3 PQC algorithm not available. Ensure BouncyCastle 1.78+ is on classpath.", e);
        }

        LOG.info("Required PQC algorithms verified successfully");
    }

    private void generateKeystoresIfNeeded() {
        try {
            String serverKeystorePath = "src/main/resources/keystores/server-hybrid-keystore.p12";
            String clientHybridKeystorePath = "src/main/resources/keystores/client-hybrid-keystore.p12";
            String clientRsaOnlyKeystorePath = "src/main/resources/keystores/client-rsa-only-keystore.p12";

            boolean keystoresExist = HybridCertificateGenerator.keystoreExists(serverKeystorePath)
                    && HybridCertificateGenerator.keystoreExists(clientHybridKeystorePath)
                    && HybridCertificateGenerator.keystoreExists(clientRsaOnlyKeystorePath);

            if (!keystoresExist) {
                LOG.info("Generating hybrid PQC keystores...");
                HybridCertificateGenerator.generateServerKeystore();
                HybridCertificateGenerator.generateClientHybridKeystore();
                HybridCertificateGenerator.generateClientRsaOnlyKeystore();
                LOG.info("✓ Hybrid PQC keystores generated successfully");
            } else {
                LOG.info("Using existing hybrid PQC keystores");
            }
        } catch (Exception e) {
            LOG.error("Failed to generate hybrid PQC keystores", e);
            throw new RuntimeException("Keystore generation failed", e);
        }
    }
}
