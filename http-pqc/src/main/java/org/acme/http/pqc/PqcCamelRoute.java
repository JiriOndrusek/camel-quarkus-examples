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

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.apache.camel.Exchange;
import org.apache.camel.builder.endpoint.EndpointRouteBuilder;

@ApplicationScoped
public class PqcCamelRoute extends EndpointRouteBuilder {

    @Inject
    CertificateValidationService validationService;

    @Inject
    HybridCertificateService hybridCertService;

    @Override
    public void configure() throws Exception {
        // Secure endpoint requiring hybrid PQC certificate validation
        from(platformHttp("/pqc/secure"))
                .routeId("pqc-secure-route")
                .log("Validating hybrid certificate for request")
                .process(exchange -> {
                    // Extract client certificate from request
                    X509Certificate clientCert = extractClientCertificate(exchange);

                    if (clientCert == null) {
                        exchange.getMessage().setHeader(Exchange.HTTP_RESPONSE_CODE, 401);
                        exchange.getMessage().setBody("✗ Authentication failed\n\n" +
                                "No client certificate provided.\n" +
                                "This endpoint requires a hybrid PQC certificate with both RSA and Dilithium3 signatures.\n");
                        return;
                    }

                    // Validate hybrid certificate
                    ValidationResult result = validationService.validateHybridCertificate(clientCert);

                    if (result.isOverallValid()) {
                        exchange.getMessage().setBody("✓ Hybrid certificate validated successfully!\n\n" +
                                "Certificate Subject: " + clientCert.getSubjectX500Principal() + "\n" +
                                "RSA signature: VALID\n" +
                                "Dilithium3 signature: VALID\n\n" +
                                "Your connection is quantum-safe!\n");
                    } else {
                        exchange.getMessage().setHeader(Exchange.HTTP_RESPONSE_CODE, 401);
                        exchange.getMessage().setBody("✗ Certificate validation failed\n\n" +
                                "Certificate Subject: " + clientCert.getSubjectX500Principal() + "\n" +
                                "RSA signature: " + (result.isRsaValid() ? "VALID" : "INVALID") + "\n" +
                                "Dilithium3 signature: " + (result.isDilithiumValid() ? "VALID" : "INVALID") + "\n\n" +
                                "Details: " + result.getMessage() + "\n");
                    }
                })
                .to(log("pqc-secure").showExchangePattern(false).showBodyType(false));

        // Hybrid certificate info endpoint
        from(platformHttp("/pqc/hybrid"))
                .routeId("pqc-hybrid-route")
                .log("Received request for hybrid certificate information")
                .process(exchange -> {
                    String info = hybridCertService.getCertificateInfo();
                    exchange.getMessage().setBody(info);
                })
                .to(log("pqc-hybrid").showExchangePattern(false).showBodyType(false));
    }

    /**
     * Extracts the client certificate from the HTTPS request.
     * Note: This requires Quarkus HTTP SSL client-auth to be enabled.
     *
     * LIMITATION: Direct extraction of client certificates from Vert.x RoutingContext
     * is not currently implemented. The RoutingContext property is not available
     * in the Camel exchange. This would require additional Quarkus/Vert.x configuration.
     *
     * For validation testing, see CertificateValidationServiceTest which tests
     * the validation logic directly.
     */
    private X509Certificate extractClientCertificate(Exchange exchange) {
        try {
            // Attempt to get Vert.x RoutingContext (currently returns null)
            RoutingContext routingContext = exchange.getProperty("CamelVertxPlatformHttpRoutingContext",
                    RoutingContext.class);

            if (routingContext != null) {
                HttpServerRequest request = routingContext.request();
                if (request != null && request.isSSL() && request.sslSession() != null) {
                    SSLSession sslSession = request.sslSession();
                    try {
                        Certificate[] peerCerts = sslSession.getPeerCertificates();
                        if (peerCerts != null && peerCerts.length > 0 && peerCerts[0] instanceof X509Certificate) {
                            return (X509Certificate) peerCerts[0];
                        }
                    } catch (SSLPeerUnverifiedException e) {
                        // No client certificate presented
                        return null;
                    }
                }
            }

            return null;
        } catch (Exception e) {
            log.warn("Failed to extract client certificate", e);
            return null;
        }
    }
}
