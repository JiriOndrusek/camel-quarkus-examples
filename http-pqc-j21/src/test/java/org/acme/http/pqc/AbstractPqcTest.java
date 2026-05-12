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
import java.util.Arrays;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import io.quarkus.test.common.QuarkusTestResource;
import io.restassured.RestAssured;
import io.restassured.config.RestAssuredConfig;
import io.restassured.config.SSLConfig;
import org.acme.http.pqc.certificates.CertificateTestResource;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.HttpResponse;
import org.jboss.logging.Logger;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Abstract base class for Apache HttpClient PQC tests with explicit provider selection.
 * Tests both BCJSSE (PQC-capable) and SunJSSE (classical only) providers.
 *
 * Certificates are generated before tests via CertificateTestResource.
 *
 * Test Pattern:
 * - PqcOnlyTest: JVM mode only (no PqcOnlyIT) - proves PQC enforcement
 * - PqcWithFallbackTest + PqcWithFallbackIT: Both JVM and native modes - proves compatibility
 *
 * Why no PqcOnlyIT?
 * Native executables can only be built with one jdk.tls.namedGroups configuration.
 * We build with fallback config (X25519MLKEM768,x25519,secp256r1) as it's more realistic
 * for production use where backward compatibility matters.
 */
@QuarkusTestResource(CertificateTestResource.class)
abstract class AbstractPqcTest {

    private static final Logger LOG = Logger.getLogger(AbstractPqcTest.class);

    void testRestAssuredConnection() throws Exception {
        // RestAssured.port is automatically set by Quarkus to the actual SSL port
        LOG.info("RestAssured test - using default JSSE provider (should be BCJSSE) on port " + RestAssured.port);

        given()
                .config(RestAssuredConfig.config().sslConfig(
                        SSLConfig.sslConfig()
                                .keyStore("target/certs/client-keystore.p12", "changeit")
                                .trustStore("target/certs/client-truststore.p12", "changeit")
                                .allowAllHostnames()))
                .baseUri("https://localhost:" + RestAssured.port)
                .when()
                .get("/pqc/secure")
                .then()
                .statusCode(200);
    }

    void testHttpClientConnection(String securityProvider, boolean expectFailure) throws Exception {
        boolean failedAsExpected = false;

        try {
            SSLContext sslContext = createSslContext(securityProvider);

            // Create custom SSLConnectionSocketFactory that explicitly sets named groups
            SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(sslContext,
                    NoopHostnameVerifier.INSTANCE) {
                @Override
                protected void prepareSocket(javax.net.ssl.SSLSocket socket) throws java.io.IOException {
                    super.prepareSocket(socket);
                    // Explicitly set named groups on the socket's SSL parameters
                    String configuredGroups = System.getProperty("jdk.tls.namedGroups", "X25519MLKEM768");
                    try {
                        SSLParameters sslParams = socket.getSSLParameters();
                        String[] namedGroupsArray = configuredGroups.split(",");
                        for (int i = 0; i < namedGroupsArray.length; i++) {
                            namedGroupsArray[i] = namedGroupsArray[i].trim();
                        }
                        sslParams.setNamedGroups(namedGroupsArray);
                        sslParams.setProtocols(new String[] { "TLSv1.3" });
                        socket.setSSLParameters(sslParams);
                        LOG.info("Set named groups on socket: " + Arrays.toString(namedGroupsArray));
                    } catch (Exception e) {
                        LOG.warn("Could not set named groups on socket: " + e.getMessage());
                    }
                }
            };

            HttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
                    .setSSLSocketFactory(sslSocketFactory)
                    .build();

            try (CloseableHttpClient httpClient = HttpClients.custom()
                    .setConnectionManager(connectionManager)
                    .build()) {

                HttpGet request = new HttpGet("https://localhost:" + RestAssured.port + "/pqc/secure");
                int responseStatus = httpClient.execute(request, HttpResponse::getCode);

                if (expectFailure) {
                    fail(securityProvider + " should have failed but got response status : " + responseStatus);
                } else {
                    assertTrue(responseStatus == 200, "Expected response status is 200");
                }
            }
        } catch (NoClassDefFoundError | ExceptionInInitializerError | javax.net.ssl.SSLHandshakeException
                | org.apache.hc.client5.http.HttpHostConnectException e) {
            if (expectFailure) {
                // Expected failure - SSL handshake should fail or connection should be refused
                LOG.info(securityProvider + " failed as expected: " + e.getClass().getSimpleName() + ": "
                        + (e.getMessage() != null ? e.getMessage() : "(no message)"));
                failedAsExpected = true;
            } else {
                // Unexpected failure - this is a real error
                String message = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                fail(securityProvider + " should have succeeded but failed with: " + message, e);
            }
        }

        if (expectFailure && !failedAsExpected) {
            fail(securityProvider + " should have failed but succeeded");
        }

    }

    protected SSLContext createSslContext(String provider) throws Exception {

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream("target/certs/client-keystore.p12")) {
            keyStore.load(fis, "changeit".toCharArray());
        }

        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream("target/certs/client-truststore.p12")) {
            trustStore.load(fis, "changeit".toCharArray());
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "changeit".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLSv1.3", provider);
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        return sslContext;
    }
}
