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

import io.quarkus.runtime.Startup;
import jakarta.enterprise.context.ApplicationScoped;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.jboss.logging.Logger;

@ApplicationScoped
@Startup
public class SecurityConfiguration {

    private static final Logger LOG = Logger.getLogger(SecurityConfiguration.class);

    public SecurityConfiguration() {
        // Insert BouncyCastle JSSE provider at position 1 (highest priority)
        // This makes BC the primary provider for all JSSE operations in this JVM,
        // enabling TLS 1.3 with PQC hybrid cipher suites (X25519MLKEM768)
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 1);

        // Configure JSSE to enable PQC hybrid key exchange algorithms
        // X25519MLKEM768 combines classical X25519 ECDH with quantum-resistant ML-KEM-768
        // NOTE: As of BouncyCastle 1.84, X25519MLKEM768 support in TLS may not be fully available
        // This configuration demonstrates the approach for when it becomes available
        String namedGroups = System.getProperty("jdk.tls.namedGroups");
        if (namedGroups == null || namedGroups.isEmpty()) {
            // Enable X25519MLKEM768 along with standard groups for compatibility
            // If x25519_mlkem768 is not recognized by the current BC version, it will fall back to x25519
            System.setProperty("jdk.tls.namedGroups",
                    "x25519_mlkem768, x25519, secp256r1, secp384r1, secp521r1");
            LOG.info("Configured TLS named groups for PQC: x25519_mlkem768, x25519, secp256r1, secp384r1, secp521r1");
            LOG.info("NOTE: If x25519_mlkem768 is not recognized, TLS will use x25519 as fallback");
        } else {
            LOG.info("TLS named groups already configured: " + namedGroups);
        }

        LOG.info("BouncyCastle JSSE provider registered for PQC TLS support");
        LOG.info("Provider: " + Security.getProvider("BCJSSE").getInfo());
    }
}
