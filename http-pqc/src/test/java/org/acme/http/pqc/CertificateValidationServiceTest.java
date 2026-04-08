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

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for hybrid PQC certificate validation.
 * Tests the validation service directly with generated hybrid and RSA-only certificates.
 */
@QuarkusTest
public class CertificateValidationServiceTest {

    @Inject
    CertificateValidationService validationService;

    @Test
    public void testHybridCertificateValidation() throws Exception {
        // Load hybrid client certificate
        X509Certificate hybridCert = loadCertificateFromKeystore(
                "src/main/resources/keystores/client-hybrid-keystore.p12",
                "client");

        // Validate - should succeed (both RSA and Dilithium3 valid)
        ValidationResult result = validationService.validateHybridCertificate(hybridCert);

        assertTrue(result.isRsaValid(), "RSA signature should be valid");
        assertTrue(result.isDilithiumValid(), "Dilithium3 signature should be valid");
        assertTrue(result.isOverallValid(), "Overall validation should succeed");
        assertNotNull(result.getMessage());
    }

    @Test
    public void testRsaOnlyCertificateValidation() throws Exception {
        // Load RSA-only client certificate (no PQC extensions)
        X509Certificate rsaOnlyCert = loadCertificateFromKeystore(
                "src/main/resources/keystores/client-rsa-only-keystore.p12",
                "client");

        // Validate - should fail (Dilithium3 missing)
        ValidationResult result = validationService.validateHybridCertificate(rsaOnlyCert);

        assertTrue(result.isRsaValid(), "RSA signature should be valid");
        assertFalse(result.isDilithiumValid(), "Dilithium3 signature should be invalid/missing");
        assertFalse(result.isOverallValid(), "Overall validation should fail");
        assertTrue(result.getMessage().contains("missing"), "Error message should indicate missing PQC signature");
    }

    private X509Certificate loadCertificateFromKeystore(String keystorePath, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            keyStore.load(fis, "changeit".toCharArray());
        }
        return (X509Certificate) keyStore.getCertificate(alias);
    }
}
