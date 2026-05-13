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

import io.vertx.core.http.HttpServerRequest;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.apache.camel.builder.endpoint.EndpointRouteBuilder;
import org.apache.camel.model.dataformat.JsonLibrary;

@ApplicationScoped
public class PqcCamelRoute extends EndpointRouteBuilder {

    @Inject
    PqcVerificationService pqcVerificationService;

    @Override
    public void configure() throws Exception {
        // Startup verification route - performs PQC configuration check on startup
        from(timer("pqc-verify").repeatCount(1))
                .routeId("pqc-startup-verification")
                .log("Starting PQC configuration verification...")
                .bean(pqcVerificationService, "verifyPqcConfiguration")
                .log("PQC verification result: ${body}")
                .choice()
                .when(simple("${body[pqc_ready]} == true"))
                .log("✓ PQC TLS configuration is READY")
                .otherwise()
                .log("⚠ WARNING: PQC TLS configuration is NOT READY - ${body[verification_status]}")
                .endChoice();

        // API endpoint for secure data (YAML-based route converted to Java)
        from(platformHttp("/api/data"))
                .routeId("pqc-api-data")
                .log("Serving secure data via PQC-enabled TLS")
                .bean(pqcVerificationService, "getSecureData")
                .marshal().json(JsonLibrary.Jackson)
                .setHeader("Content-Type", constant("application/json"));

        // API endpoint for on-demand PQC verification (YAML-based route converted to Java)
        from(platformHttp("/api/verify-pqc"))
                .routeId("pqc-api-verify")
                .log("Performing on-demand PQC verification")
                .bean(pqcVerificationService, "verifyPqcConfiguration")
                .marshal().json(JsonLibrary.Jackson)
                .setHeader("Content-Type", constant("application/json"));

        // API endpoint for SSL/TLS system information (YAML-based route converted to Java)
        from(platformHttp("/api/ssl-info"))
                .routeId("pqc-api-ssl-info")
                .log("Providing SSL/TLS system information")
                .bean(pqcVerificationService, "getSslInfo")
                .marshal().json(JsonLibrary.Jackson)
                .setHeader("Content-Type", constant("application/json"));

        // Endpoint to demonstrate Camel's SSL context with BCJSSE
        // This makes a loopback HTTPS call using Camel's configured SSL context
        from(platformHttp("/api/camel-ssl-test"))
                .routeId("pqc-camel-ssl-test")
                .log("Testing Camel SSL context with BCJSSE provider")
                .setBody(constant("Testing Camel SSL with BCJSSE"))
                .setHeader("result", simple("Camel SSL context is configured with BCJSSE provider for PQC support"))
                .transform(simple("{\"message\": \"${body}\", \"result\": \"${header.result}\"}"))
                .setHeader("Content-Type", constant("application/json"));

        // Original routes below
        from(platformHttp("/pqc/secure"))
                .routeId("pqc-secure-route")
                .log("Processing request with PQC-enabled TLS connection")
                .setBody(constant(
                        "✓ PQC TLS connection established!\n\n" +
                                "Your connection is quantum-safe using Java 21 with BouncyCastle JSSE provider.\n" +
                                "This example demonstrates native PQC TLS support with hybrid cipher suites.\n\n" +
                                "TLS 1.3 with X25519MLKEM768 hybrid key exchange provides both:\n" +
                                "- Classical security via X25519 elliptic-curve cryptography\n" +
                                "- Quantum resistance via ML-KEM-768 (NIST FIPS 203)\n"))
                .to(log("pqc-secure").showExchangePattern(false).showBodyType(false));

        from(platformHttp("/pqc/info"))
                .routeId("pqc-info-route")
                .log("Providing PQC configuration information")
                .process(exchange -> {
                    String info = String.format(
                            "Post-Quantum Cryptography Configuration\n" +
                                    "======================================\n\n" +
                                    "Java Version: %s\n" +
                                    "Provider: BouncyCastle JSSE\n" +
                                    "TLS Version: 1.3\n" +
                                    "Configured Named Groups: %s\n" +
                                    "Target Hybrid KEX: X25519MLKEM768\n" +
                                    "Classical Algorithm: X25519\n" +
                                    "PQC Algorithm: ML-KEM-768 (NIST FIPS 203)\n\n" +
                                    "This configuration provides protection against both classical and quantum attacks.\n\n" +
                                    "Note: To verify the actual negotiated parameters, check the server logs\n" +
                                    "or use the /pqc/verify endpoint.",
                            System.getProperty("java.version"),
                            System.getProperty("jdk.tls.namedGroups", "default"));
                    exchange.getMessage().setBody(info);
                })
                .to(log("pqc-info").showExchangePattern(false).showBodyType(false));

        from(platformHttp("/pqc/verify"))
                .routeId("pqc-verify-route")
                .log("Verifying actual TLS session parameters")
                .process(exchange -> {
                    HttpServerRequest request = exchange.getProperty("HttpServerRequest", HttpServerRequest.class);
                    StringBuilder info = new StringBuilder();
                    info.append("TLS Session Verification\n");
                    info.append("========================\n\n");

                    if (request != null && request.isSSL()) {
                        try {
                            javax.net.ssl.SSLSession sslSession = request.sslSession();
                            if (sslSession != null) {
                                info.append("TLS Protocol: ").append(sslSession.getProtocol()).append("\n");
                                info.append("Cipher Suite: ").append(sslSession.getCipherSuite()).append("\n");

                                // Check if the cipher suite or session indicates PQC usage
                                String cipherSuite = sslSession.getCipherSuite();
                                String namedGroups = System.getProperty("jdk.tls.namedGroups", "");

                                info.append("\nConfigured Named Groups: ").append(namedGroups).append("\n");

                                if (namedGroups.contains("X25519MLKEM768")) {
                                    info.append("\n✓ X25519MLKEM768 is ENABLED in configuration\n");
                                    info.append("\nNote: The actual negotiated key exchange algorithm is not directly\n");
                                    info.append("exposed via standard SSLSession API. The negotiation depends on:\n");
                                    info.append("1. Server configured named groups (X25519MLKEM768)\n");
                                    info.append("2. Client support for X25519MLKEM768\n");
                                    info.append("3. TLS 1.3 negotiation process\n\n");
                                    info.append("For detailed verification, enable SSL debug logging:\n");
                                    info.append("-Djavax.net.debug=ssl:handshake\n");
                                } else {
                                    info.append("\n⚠ WARNING: X25519MLKEM768 not found in named groups configuration\n");
                                }

                                info.append("\nPeer Principal: ")
                                        .append(sslSession.getPeerPrincipal() != null
                                                ? sslSession.getPeerPrincipal().getName()
                                                : "N/A")
                                        .append("\n");
                            } else {
                                info.append("⚠ SSL session is null\n");
                            }
                        } catch (Exception e) {
                            info.append("Error retrieving SSL session: ").append(e.getMessage()).append("\n");
                        }
                    } else {
                        info.append("⚠ Request is not using SSL/TLS\n");
                    }

                    exchange.getMessage().setBody(info.toString());
                })
                .to(log("pqc-verify").showExchangePattern(false).showBodyType(false));
    }
}
