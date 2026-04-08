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
package org.acme.http.pqc.trustmanager;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Custom X509TrustManager that validates hybrid PQC certificates at the TLS layer.
 *
 * This TrustManager validates both RSA and Dilithium3 signatures during the TLS handshake,
 * rejecting connections with invalid or RSA-only certificates before the application layer
 * sees the request.
 */
public class HybridPqcX509TrustManager implements X509TrustManager {

    private static final Logger LOG = LoggerFactory.getLogger(HybridPqcX509TrustManager.class);

    private final CertificateValidationService validationService;

    public HybridPqcX509TrustManager(CertificateValidationService validationService) {
        this.validationService = validationService;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("Client certificate chain is empty");
        }

        X509Certificate clientCert = chain[0];
        LOG.info("Validating client certificate at TLS layer: {}", clientCert.getSubjectX500Principal());

        // Validate hybrid certificate using existing service
        ValidationResult result = validationService.validateHybridCertificate(clientCert);

        if (!result.isOverallValid()) {
            String errorMsg = String.format(
                    "Hybrid PQC certificate validation failed: RSA=%s, Dilithium3=%s - %s",
                    result.isRsaValid() ? "VALID" : "INVALID",
                    result.isDilithiumValid() ? "VALID" : "INVALID",
                    result.getMessage());
            LOG.error(errorMsg);
            throw new CertificateException(errorMsg);
        }

        LOG.info("✓ Client certificate validated successfully at TLS layer (RSA + Dilithium3)");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        // For server-to-server TLS validation (not needed for this example)
        // Could implement similar hybrid validation for server certificates
        LOG.debug("Server certificate validation not implemented (client-side validation only)");
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        // Return empty array for self-signed certificates in demo
        // In production, return trusted CA certificates
        return new X509Certificate[0];
    }
}
