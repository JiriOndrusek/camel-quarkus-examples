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
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.jboss.logging.Logger;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Abstract base class for Apache HttpClient PQC tests with explicit provider selection.
 * Tests both BCJSSE (PQC-capable) and SunJSSE (classical only) providers.
 *
 * Certificates are generated before tests via CertificateTestResource.
 */
@QuarkusTestResource(CertificateTestResource.class)
abstract class AbstractPqcTest {

    private static final Logger LOG = Logger.getLogger(AbstractPqcTest.class);

    void testRestAssuredConnection() throws Exception {
        int port = RestAssured.port > 0 ? RestAssured.port : 8443;

        // RestAssured will use the default JSSE provider which is BCJSSE
        // (registered at position 2 in CertificateTestResource)
        // Configure keystore and truststore - RestAssured will create its own SSLContext
        // using the default provider which supports X25519MLKEM768
        LOG.info("RestAssured test - using default JSSE provider (should be BCJSSE)");

        given()
                .config(RestAssuredConfig.config().sslConfig(
                        SSLConfig.sslConfig()
                                .keyStore("target/certs/client-keystore.p12", "changeit")
                                .trustStore("target/certs/client-truststore.p12", "changeit")
                                .allowAllHostnames()))
                .baseUri("https://localhost:" + port)
                .when()
                .get("/pqc/secure")
                .then()
                .statusCode(200);
    }

    void testHttpClientConnection(String securityProvider, boolean expectFailure) throws Exception {
        boolean failedAsExpected = false;

        try {
            int port = RestAssured.port > 0 ? RestAssured.port : 8443;
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

                HttpGet request = new HttpGet("https://localhost:" + port + "/api/data");
                String response = httpClient.execute(request, httpResponse -> {
                    int statusCode = httpResponse.getCode();
                    EntityUtils.toString(httpResponse.getEntity());
                    return "Status: " + statusCode;
                });

                //todo better assertion of failure
                if (expectFailure) {
                    if (response.contains("404")) {
                        //todo works differently in jvm
                        failedAsExpected = true;
                    } else {
                        fail(securityProvider + " should have failed but got: " + response);
                    }
                }
            }
        } catch (NoClassDefFoundError | ExceptionInInitializerError | javax.net.ssl.SSLHandshakeException
                | org.apache.hc.client5.http.HttpHostConnectException e) {
            if (expectFailure) {
                failedAsExpected = true;
            } else {
                throw e;
            }
        }

        if (expectFailure && !failedAsExpected) {
            fail(securityProvider + " should have failed with X25519MLKEM768");
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
