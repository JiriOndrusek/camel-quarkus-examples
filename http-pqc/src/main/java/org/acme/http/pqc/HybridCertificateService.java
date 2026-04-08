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

import java.security.cert.X509Certificate;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service demonstrating Chimera hybrid certificates combining classical RSA
 * and post-quantum Dilithium signatures. Uses X.509 extensions for alternative
 * public key and signature as described in the BouncyCastle PQC Almanac.
 */
@ApplicationScoped
public class HybridCertificateService {

    private static final Logger LOG = LoggerFactory.getLogger(HybridCertificateService.class);

    private X509Certificate serverCertificate;

    @PostConstruct
    public void init() {
        try {
            LOG.info("Loading server hybrid certificate...");
            serverCertificate = loadServerCertificate();
            LOG.info("Server hybrid certificate loaded successfully");
        } catch (Exception e) {
            LOG.error("Failed to load server certificate", e);
            throw new RuntimeException("Server certificate loading failed", e);
        }
    }

    /**
     * Loads the server certificate from the keystore.
     */
    private X509Certificate loadServerCertificate() throws Exception {
        String keystorePath = "src/main/resources/keystores/server-hybrid-keystore.p12";
        String password = "changeit";

        java.io.FileInputStream fis = new java.io.FileInputStream(keystorePath);
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS12");
        keyStore.load(fis, password.toCharArray());
        fis.close();

        return (X509Certificate) keyStore.getCertificate("server");
    }

    public X509Certificate getServerCertificate() {
        return serverCertificate;
    }

    public String getCertificateInfo() {
        StringBuilder info = new StringBuilder();
        info.append("Chimera Hybrid Certificate Information\n");
        info.append("======================================\n\n");
        info.append("Format: Chimera (X.509 with alternative key/signature extensions)\n");
        info.append("Primary Algorithm: RSA-2048 + SHA256withRSA\n");
        info.append("Alternative Algorithm: Dilithium3 (ML-DSA-65 / FIPS 204)\n\n");
        info.append("Subject: ").append(serverCertificate.getSubjectX500Principal()).append("\n");
        info.append("Issuer: ").append(serverCertificate.getIssuerX500Principal()).append("\n");
        info.append("Serial: ").append(serverCertificate.getSerialNumber()).append("\n");
        info.append("Valid from: ").append(serverCertificate.getNotBefore()).append("\n");
        info.append("Valid until: ").append(serverCertificate.getNotAfter()).append("\n\n");

        info.append("X.509 Extensions:\n");
        info.append("  - altSubjectPublicKeyInfo (OID 2.5.29.72): Dilithium3 public key\n");
        info.append("  - altSignatureAlgorithm (OID 2.5.29.73): Dilithium3 signature algorithm\n");
        info.append("  - altSignatureValue (OID 2.5.29.74): Dilithium3 signature\n\n");

        info.append("Security: Dual protection - quantum-safe AND classically secure\n");
        info.append("Verification: Both RSA and Dilithium3 signatures must be valid\n");

        return info.toString();
    }
}
