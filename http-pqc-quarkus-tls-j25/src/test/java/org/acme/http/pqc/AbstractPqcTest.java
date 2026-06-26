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
import java.util.concurrent.CompletionException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import io.restassured.RestAssured;
import io.restassured.config.RestAssuredConfig;
import io.restassured.config.SSLConfig;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.net.OpenSSLEngineOptions;
import io.vertx.core.net.PfxOptions;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.jboss.logging.Logger;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Abstract base class for PQC tests using JDK 25+ native SunJSSE.
 *
 * Provides two client approaches:
 * - JSSE HttpClient5 with configurable named groups ({@link #testHttpClientConnection})
 * - Vert.x WebClient with OpenSSL backend for hybrid PQC ({@link #testWebClientConnection})
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
            int responseStatus = httpClient.execute(request, org.apache.hc.core5.http.HttpResponse::getCode);

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

    /**
     * Test connection using Vert.x WebClient with OpenSSL backend.
     *
     * @param useKeyExchange     if true, enables OpenSSL engine with hybrid PQC key exchange
     * @param expectFailure if true, expects the connection to fail (SSLException)
     */
    void testWebClientConnection(boolean useKeyExchange, boolean expectFailure) {
        WebClientOptions options = new WebClientOptions();
        options.setSsl(true);
        options.setKeyCertOptions(new PfxOptions()
                .setPath("target/certs/client-keystore.p12")
                .setPassword("changeit"));

        if (useKeyExchange) {
            options.setSslEngineOptions(new OpenSSLEngineOptions());
            options.setUseHybridKeyExchangeProtocol(true);
            options.setTrustOptions(new PfxOptions()
                    .setPath("target/certs/client-truststore.p12")
                    .setPassword("changeit"));
        } else {
            options.setTrustAll(true);
        }

        Vertx vertx = Vertx.vertx();
        WebClient client = WebClient.create(vertx, options);
        String url = "https://localhost:" + RestAssured.port + "/pqc/secure";

        if (expectFailure) {
            CompletionException ex = assertThrows(CompletionException.class, () -> client
                    .getAbs(url).send().toCompletionStage().toCompletableFuture().join());
            Throwable cause = ex.getCause();
            assertTrue(cause instanceof javax.net.ssl.SSLException,
                    "Expected SSLException but got: " + cause.getClass().getName() + ": " + cause.getMessage());
            LOG.info("Connection failed with SSLException as expected: " + cause.getMessage());
        } else {
            HttpResponse<Buffer> response = client
                    .getAbs(url).send().toCompletionStage().toCompletableFuture().join();
            assertEquals(200, response.statusCode());
            LOG.info("Connection succeeded: " + response.bodyAsString());
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
