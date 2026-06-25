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

import io.restassured.RestAssured;
import io.restassured.config.RestAssuredConfig;
import io.restassured.config.SSLConfig;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.HttpResponse;
import org.jboss.logging.Logger;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Abstract base class for PQC tests using JDK 25+ native SunJSSE.
 *
 * Unlike the JDK 21 example, no BouncyCastle JSSE provider registration is needed.
 * JDK 25+ SunJSSE natively supports X25519MLKEM768 hybrid key exchange.
 */
abstract class AbstractPqcTest {

    private static final Logger LOG = Logger.getLogger(AbstractPqcTest.class);

    static final String[] DEFAULT_NAMED_GROUPS = { "X25519MLKEM768", "x25519", "secp256r1" };

    void testRestAssuredConnection() throws Exception {
        LOG.info("RestAssured test - using default SunJSSE on port " + RestAssured.port);

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

    void testHttpClientConnection(String[] namedGroups, boolean expectFailure) throws Exception {
        SSLContext sslContext = createSslContext();

        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(sslContext,
                NoopHostnameVerifier.INSTANCE) {
            @Override
            protected void prepareSocket(javax.net.ssl.SSLSocket socket) throws java.io.IOException {
                super.prepareSocket(socket);
                try {
                    SSLParameters sslParams = socket.getSSLParameters();
                    sslParams.setNamedGroups(namedGroups);
                    sslParams.setProtocols(new String[] { "TLSv1.3" });
                    socket.setSSLParameters(sslParams);
                    LOG.info("Set named groups on socket: " + Arrays.toString(namedGroups));
                } catch (Exception e) {
                    LOG.warn("Could not set named groups on socket: " + e.getMessage());
                }
            }
        };

        try (PoolingHttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder
                .create()
                .setSSLSocketFactory(sslSocketFactory)
                .build();
                CloseableHttpClient httpClient = HttpClients.custom()
                        .setConnectionManager(connectionManager)
                        .build()) {

            HttpGet request = new HttpGet("https://localhost:" + RestAssured.port + "/pqc/secure");
            int responseStatus = httpClient.execute(request, HttpResponse::getCode);

            if (expectFailure) {
                fail("Connection should have failed but got response status: " + responseStatus);
            } else {
                assertTrue(responseStatus == 200, "Expected response status is 200");
            }
        } catch (java.io.IOException e) {
            if (!expectFailure) {
                fail("Connection should have succeeded but failed: " + e.getMessage());
            }
            LOG.info("Connection failed as expected: " + e.getMessage());
        }
    }

    protected SSLContext createSslContext() throws Exception {
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

        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        return sslContext;
    }
}
