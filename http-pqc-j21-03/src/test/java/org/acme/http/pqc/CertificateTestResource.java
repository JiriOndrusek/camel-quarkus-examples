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
        // Register BouncyCastle provider for certificate generation
        // This runs before Quarkus startup, so we need to register it here
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
            LOG.info("Registered BouncyCastleProvider for certificate generation");
        }

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
