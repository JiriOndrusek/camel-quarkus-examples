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
import org.apache.camel.model.dataformat.JsonLibrary;

/**
 * Camel routes based on oscerd/camel-pqc-tls example.
 * Source:
 * https://github.com/oscerd/camel-pqc-tls/blob/main/pqc-ssl-context-jdk21/src/main/resources/camel/pqc-ssl-context.camel.yaml
 */
@ApplicationScoped
public class PqcCamelRoute extends EndpointRouteBuilder {

    @Inject
    PqcVerificationService pqcVerificationService;

    @Override
    public void configure() throws Exception {
        // Startup verification route - performs PQC configuration check on startup
        // Equivalent to 'pqc-verify' route in oscerd YAML
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

        // API endpoint for secure data
        // Equivalent to 'pqc-secure-server' route in oscerd YAML
        from(platformHttp("/api/data"))
                .routeId("pqc-api-data")
                .log("Serving secure data via PQC-enabled TLS")
                .bean(pqcVerificationService, "getSecureData")
                .marshal().json(JsonLibrary.Jackson)
                .setHeader("Content-Type", constant("application/json"));

        // API endpoint for on-demand PQC verification
        // Equivalent to 'pqc-verify-endpoint' route in oscerd YAML
        from(platformHttp("/api/verify-pqc"))
                .routeId("pqc-api-verify")
                .log("Performing on-demand PQC verification")
                .bean(pqcVerificationService, "verifyPqcConfiguration")
                .marshal().json(JsonLibrary.Jackson)
                .setHeader("Content-Type", constant("application/json"));

        // API endpoint for SSL/TLS system information
        // Equivalent to 'pqc-ssl-info' route in oscerd YAML
        from(platformHttp("/api/ssl-info"))
                .routeId("pqc-api-ssl-info")
                .log("Providing SSL/TLS system information")
                .bean(pqcVerificationService, "getSslInfo")
                .marshal().json(JsonLibrary.Jackson)
                .setHeader("Content-Type", constant("application/json"));
    }
}
