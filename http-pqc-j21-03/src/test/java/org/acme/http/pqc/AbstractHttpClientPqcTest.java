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

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManagerFactory;

import io.restassured.RestAssured;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * Abstract base class for Apache HttpClient PQC tests with explicit provider selection.
 * Tests both BCJSSE (PQC-capable) and SunJSSE (classical only) providers.
 */
abstract class AbstractHttpClientPqcTest {

    /**
     * Returns the test description for BCJSSE test.
     */
    protected abstract String getBcjsseTestDescription();

    /**
     * Returns the test description for SunJSSE test.
     */
    protected abstract String getSunJsseTestDescription();

    /**
     * Validates the named groups configuration.
     */
    protected abstract void validateNamedGroups(String actualNamedGroups);

    /**
     * Returns additional note to display before SunJSSE test (optional).
     */
    protected String getSunJsseFailureNote() {
        return null;
    }

    @Test
    void testBcjsseSucceeds() throws Exception {
        String actualNamedGroups = System.getProperty("jdk.tls.namedGroups");

        System.out.println("\n═══════════════════════════════════════════════════════════");
        System.out.println("   " + getBcjsseTestDescription());
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Server: " + actualNamedGroups);
        System.out.println("Client: Apache HttpClient with BCJSSE");
        System.out.println();

        validateNamedGroups(actualNamedGroups);

        int port = RestAssured.port > 0 ? RestAssured.port : 8443;
        SSLContext sslContext = createSslContext("BCJSSE");

        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                sslContext,
                NoopHostnameVerifier.INSTANCE);

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

            System.out.println("✓ SUCCESS - " + response);
            System.out.println("  BCJSSE negotiated " + actualNamedGroups);
        }

        System.out.println("═══════════════════════════════════════════════════════════\n");
    }

    @Test
    void testSunJsseFails() throws Exception {
        String actualNamedGroups = System.getProperty("jdk.tls.namedGroups");

        System.out.println("\n═══════════════════════════════════════════════════════════");
        System.out.println("   " + getSunJsseTestDescription());
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Server: " + actualNamedGroups);
        System.out.println("Client: Apache HttpClient with SunJSSE");
        System.out.println();

        validateNamedGroups(actualNamedGroups);

        String note = getSunJsseFailureNote();
        if (note != null) {
            System.out.println(note);
            System.out.println();
        }

        int port = RestAssured.port > 0 ? RestAssured.port : 8443;

        boolean failedAsExpected = false;
        try {
            SSLContext sslContext = createSslContext("SunJSSE");

            SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                    sslContext,
                    NoopHostnameVerifier.INSTANCE);

            HttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
                    .setSSLSocketFactory(sslSocketFactory)
                    .build();

            try (CloseableHttpClient httpClient = HttpClients.custom()
                    .setConnectionManager(connectionManager)
                    .build()) {

                HttpGet request = new HttpGet("https://localhost:" + port + "/api/data");
                String response = httpClient.execute(request, httpResponse -> {
                    int statusCode = httpResponse.getCode();
                    String body = EntityUtils.toString(httpResponse.getEntity());
                    return "Status: " + statusCode + ", Body: " + body;
                });

                fail("SunJSSE should have failed but got: " + response);
            }
        } catch (SSLHandshakeException e) {
            System.out.println("✓ FAILED as expected (handshake error)");
            System.out.println("  Error: " + e.getMessage());
            failedAsExpected = true;
        } catch (ExceptionInInitializerError e) {
            Throwable cause = e.getCause();
            if (cause != null && cause.getMessage().contains("contains no supported named groups")) {
                System.out.println("✓ FAILED as expected (initialization error)");
                System.out.println("  Error: " + cause.getMessage());
                failedAsExpected = true;
            } else {
                throw e;
            }
        } catch (NoClassDefFoundError e) {
            System.out.println("✓ FAILED as expected (initialization error)");
            System.out.println("  SunJSSE cannot parse jdk.tls.namedGroups containing X25519MLKEM768");
            failedAsExpected = true;
        } catch (Exception e) {
            System.out.println("✓ FAILED as expected: " + e.getClass().getSimpleName());
            System.out.println("  Error: " + e.getMessage());
            failedAsExpected = true;
        }

        if (failedAsExpected) {
            System.out.println();
            System.out.println("  This proves X25519MLKEM768 requires BouncyCastle JSSE");
        } else {
            fail("SunJSSE should have failed with X25519MLKEM768 in jdk.tls.namedGroups");
        }

        System.out.println("═══════════════════════════════════════════════════════════\n");
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
