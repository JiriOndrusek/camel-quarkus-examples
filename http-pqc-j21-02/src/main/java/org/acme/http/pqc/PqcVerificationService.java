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

import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Named;
import org.jboss.logging.Logger;

/**
 * Service bean that provides PQC verification and system information.
 * Used by YAML-based Camel routes.
 */
@ApplicationScoped
@Named("pqcVerificationService")
@RegisterForReflection
public class PqcVerificationService {

    private static final Logger LOG = Logger.getLogger(PqcVerificationService.class);

    /**
     * Performs comprehensive PQC configuration verification.
     * Returns a map with verification results suitable for JSON serialization.
     */
    public Map<String, Object> verifyPqcConfiguration() {
        Map<String, Object> result = new HashMap<>();

        try {
            // Check BCJSSE provider
            Provider bcjsseProvider = Security.getProvider("BCJSSE");
            boolean bcjssePresent = bcjsseProvider != null;
            result.put("bcjsse_provider_present", bcjssePresent);

            if (bcjssePresent) {
                Provider[] providers = Security.getProviders();
                int bcjssePosition = -1;
                for (int i = 0; i < providers.length; i++) {
                    if ("BCJSSE".equals(providers[i].getName())) {
                        bcjssePosition = i + 1;
                        break;
                    }
                }
                result.put("bcjsse_position", bcjssePosition);
                result.put("bcjsse_position_correct", bcjssePosition == 1);
                result.put("bcjsse_info", bcjsseProvider.getInfo());
            }

            // Check BC provider
            Provider bcProvider = Security.getProvider("BC");
            result.put("bc_provider_present", bcProvider != null);

            // Check named groups configuration
            String namedGroups = System.getProperty("jdk.tls.namedGroups", "");
            result.put("named_groups", namedGroups);
            result.put("x25519mlkem768_configured", namedGroups.contains("X25519MLKEM768"));

            // Check disabled algorithms
            String disabledAlgorithms = Security.getProperty("jdk.tls.disabledAlgorithms");
            boolean ecdhDisabled = disabledAlgorithms != null && disabledAlgorithms.contains("ECDH");
            result.put("ecdh_disabled", ecdhDisabled);

            // Overall verification status
            boolean pqcReady = bcjssePresent &&
                    bcProvider != null &&
                    namedGroups.contains("X25519MLKEM768") &&
                    !ecdhDisabled;
            result.put("pqc_ready", pqcReady);
            result.put("verification_status", pqcReady ? "READY" : "NOT_READY");

            LOG.info("PQC verification completed: " + (pqcReady ? "READY" : "NOT READY"));

        } catch (Exception e) {
            LOG.error("Error during PQC verification", e);
            result.put("error", e.getMessage());
            result.put("verification_status", "ERROR");
        }

        return result;
    }

    /**
     * Returns system SSL/TLS information.
     */
    public Map<String, Object> getSslInfo() {
        Map<String, Object> result = new HashMap<>();

        result.put("java_version", System.getProperty("java.version"));
        result.put("java_vendor", System.getProperty("java.vendor"));

        // List all security providers
        Provider[] providers = Security.getProviders();
        String[] providerNames = new String[providers.length];
        for (int i = 0; i < providers.length; i++) {
            providerNames[i] = providers[i].getName();
        }
        result.put("security_providers", providerNames);

        // TLS configuration
        result.put("jdk_tls_named_groups", System.getProperty("jdk.tls.namedGroups", "default"));
        result.put("jdk_tls_disabled_algorithms", Security.getProperty("jdk.tls.disabledAlgorithms"));

        return result;
    }

    /**
     * Returns a simple data payload for testing endpoint availability.
     */
    public Map<String, Object> getSecureData() {
        Map<String, Object> result = new HashMap<>();
        result.put("message", "PQC-secured data endpoint");
        result.put("timestamp", System.currentTimeMillis());
        result.put("pqc_enabled", true);
        result.put("tls_version", "1.3");
        result.put("key_exchange", "X25519MLKEM768 (hybrid)");
        return result;
    }
}
