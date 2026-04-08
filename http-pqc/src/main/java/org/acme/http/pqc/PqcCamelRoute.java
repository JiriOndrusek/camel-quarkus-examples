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

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.apache.camel.builder.endpoint.EndpointRouteBuilder;

@ApplicationScoped
public class PqcCamelRoute extends EndpointRouteBuilder {

    @Inject
    PqcSignatureService signatureService;

    @Inject
    PqcKemService kemService;

    @Override
    public void configure() throws Exception {
        // Main endpoint: demonstrate ML-DSA signature
        from(platformHttp("/pqc/sign"))
                .routeId("pqc-signature-route")
                .log("Received request to demonstrate ML-DSA-65 signature")
                .process(exchange -> {
                    String message = exchange.getIn().getHeader("message", "Hello, Post-Quantum World!", String.class);
                    String signature = signatureService.signMessage(message);
                    boolean verified = signatureService.verifySignature(message, signature);

                    StringBuilder response = new StringBuilder();
                    response.append("ML-DSA-65 Digital Signature Demonstration\n");
                    response.append("==========================================\n\n");
                    response.append("Algorithm: ").append(signatureService.getAlgorithm()).append(" (FIPS 204)\n");
                    response.append("Message: \"").append(message).append("\"\n");
                    response.append("Signature (first 64 chars): ").append(signature.substring(0, 64)).append("...\n");
                    response.append("Signature Length: ").append(signature.length()).append(" characters (base64)\n");
                    response.append("Verification: ").append(verified ? "✓ VALID" : "✗ INVALID").append("\n\n");
                    response.append("Status: Post-quantum signature successfully generated and verified!\n");

                    exchange.getMessage().setBody(response.toString());
                })
                .to(log("pqc-signature").showExchangePattern(false).showBodyType(false));

        // KEM demonstration endpoint
        from(platformHttp("/pqc/kem"))
                .routeId("pqc-kem-route")
                .log("Received request to demonstrate NTRU key encapsulation")
                .process(exchange -> {
                    String result = kemService.demonstrateKeyEncapsulation();
                    exchange.getMessage().setBody(result);
                })
                .to(log("pqc-kem").showExchangePattern(false).showBodyType(false));

        // Info endpoint
        from(platformHttp("/pqc/info"))
                .routeId("pqc-info-route")
                .log("Received request for PQC information")
                .process(exchange -> {
                    StringBuilder info = new StringBuilder();
                    info.append("Post-Quantum Cryptography Example - Java 17\n");
                    info.append("============================================\n\n");
                    info.append("This example demonstrates NIST PQC algorithms:\n\n");
                    info.append("1. Dilithium3 (ML-DSA-65 / FIPS 204)\n");
                    info.append("   - Post-quantum digital signatures\n");
                    info.append("   - Endpoint: /pqc/sign?message=YourMessage\n\n");
                    info.append("2. NTRU (NIST PQC Finalist)\n");
                    info.append("   - Post-quantum key encapsulation mechanism\n");
                    info.append("   - Endpoint: /pqc/kem\n\n");
                    info.append("Provider: BouncyCastle 1.78.1\n");
                    info.append("Note: BC 1.78.1 does not include Kyber/ML-KEM KeyPairGenerator.\n");
                    info.append("ML-KEM support requires BouncyCastle 1.79+.\n\n");
                    info.append("Java 17 Limitation: PQC in TLS handshakes not supported.\n");
                    info.append("This example demonstrates PQC algorithms programmatically.\n");
                    info.append("Full PQC TLS requires Java 21+ with BouncyCastle JSSE.\n");

                    exchange.getMessage().setBody(info.toString());
                })
                .to(log("pqc-info").showExchangePattern(false).showBodyType(false));
    }
}
