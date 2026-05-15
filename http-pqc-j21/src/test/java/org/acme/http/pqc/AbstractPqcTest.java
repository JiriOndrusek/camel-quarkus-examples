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

                System.out.println(">>>>> respinse: " + response);
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
        // jdk.tls.namedGroups is already configured in CertificateTestResource.start()
        // before any SSL contexts are created

        //        LOG.info("=== Creating SSL context with provider: " + provider + " ===");
        //        LOG.info("System property jdk.tls.namedGroups: " + System.getProperty("jdk.tls.namedGroups"));

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

        //         Log available cipher suites and parameters
        //        SSLParameters params = sslContext.getDefaultSSLParameters();
        //        LOG.info("Default cipher suites (" + params.getCipherSuites().length + "): " +
        //                Arrays.toString(params.getCipherSuites()));

        //        SSLParameters supportedParams = sslContext.getSupportedSSLParameters();
        //        LOG.info("Supported cipher suites (" + supportedParams.getCipherSuites().length + "): " +
        //                Arrays.toString(supportedParams.getCipherSuites()));
        //        LOG.info("Supported protocols: " + Arrays.toString(supportedParams.getProtocols()));
        //
        //         Log named groups BEFORE explicit setting
        //        try {
        //            String[] namedGroups = params.getNamedGroups();
        //            LOG.info("Named groups (before): " + (namedGroups != null ? Arrays.toString(namedGroups) : "null"));
        //        } catch (Exception e) {
        //            LOG.info("Named groups (before) not available: " + e.getMessage());
        //        }

        //        // Check if X25519MLKEM768 is supported by querying BouncyCastle NamedGroup class
        //        try {
        //            Class<?> namedGroupClass = Class.forName("org.bouncycastle.tls.NamedGroup");
        //            java.lang.reflect.Field[] fields = namedGroupClass.getDeclaredFields();
        //            LOG.info("BouncyCastle NamedGroup class has " + fields.length + " fields");
        //            boolean foundX25519MLKEM768 = false;
        //            for (java.lang.reflect.Field field : fields) {
        //                if (java.lang.reflect.Modifier.isStatic(field.getModifiers()) &&
        //                        field.getType() == int.class) {
        //                    if (field.getName().contains("X25519") || field.getName().contains("MLKEM") ||
        //                            field.getName().contains("mlkem") || field.getName().contains("x25519")) {
        //                        field.setAccessible(true);
        //                        LOG.info("Found NamedGroup constant: " + field.getName() + " = 0x" +
        //                                Integer.toHexString(field.getInt(null)));
        //                        if (field.getName().toLowerCase().contains("x25519mlkem768") ||
        //                                field.getName().equals("X25519_MLKEM768")) {
        //                            foundX25519MLKEM768 = true;
        //                        }
        //                    }
        //                }
        //            }
        //            LOG.info("X25519MLKEM768 constant found in NamedGroup: " + foundX25519MLKEM768);
        //        } catch (Exception e) {
        //            LOG.warn("Could not inspect BouncyCastle NamedGroup class: " + e.getMessage(), e);
        //        }
        //
        //        // Try to check what named groups the BCJSSE provider actually supports
        //        try {
        //            Class<?> namedGroupInfoClass = Class.forName("org.bouncycastle.jsse.provider.NamedGroupInfo");
        //            java.lang.reflect.Method getNamedGroupsMethod = null;
        //            for (java.lang.reflect.Method m : namedGroupInfoClass.getDeclaredMethods()) {
        //                if (m.getName().contains("getNamedGroup") || m.getName().contains("getSupportedGroups") ||
        //                        m.getName().contains("getAll")) {
        //                    LOG.info("Found NamedGroupInfo method: " + m.getName());
        //                }
        //            }
        //        } catch (Exception e) {
        //            LOG.warn("Could not inspect BouncyCastle NamedGroupInfo class: " + e.getMessage());
        //        }
        //
        //        // Check if ML-KEM and XDH algorithms are available (required for X25519MLKEM768)
        //        java.security.Provider bcProvider = java.security.Security.getProvider("BC");
        //        java.security.Provider bcjsseProvider = java.security.Security.getProvider("BCJSSE");
        //
        //        LOG.info("Checking for ML-KEM and XDH algorithm availability:");
        //        try {
        //            javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("ML-KEM", bcProvider);
        //            LOG.info("ML-KEM KeyAgreement: AVAILABLE");
        //        } catch (Exception e) {
        //            LOG.warn("ML-KEM KeyAgreement: NOT AVAILABLE - " + e.getMessage());
        //        }
        //
        //        try {
        //            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("ML-KEM", bcProvider);
        //            LOG.info("ML-KEM KeyPairGenerator: AVAILABLE");
        //        } catch (Exception e) {
        //            LOG.warn("ML-KEM KeyPairGenerator: NOT AVAILABLE - " + e.getMessage());
        //        }
        //
        //        try {
        //            javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("XDH", bcProvider);
        //            LOG.info("XDH KeyAgreement: AVAILABLE");
        //        } catch (Exception e) {
        //            LOG.warn("XDH KeyAgreement: NOT AVAILABLE - " + e.getMessage());
        //        }
        //
        //        try {
        //            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("XDH", bcProvider);
        //            LOG.info("XDH KeyPairGenerator: AVAILABLE");
        //        } catch (Exception e) {
        //            LOG.warn("XDH KeyPairGenerator: NOT AVAILABLE - " + e.getMessage());
        //        }
        //
        //        // List all services provided by BC provider
        //        if (bcProvider != null) {
        //            java.util.Set<java.security.Provider.Service> services = bcProvider.getServices();
        //            long mlkemCount = services.stream()
        //                    .filter(s -> s.getAlgorithm().contains("ML") || s.getAlgorithm().contains("KEM") ||
        //                            s.getAlgorithm().contains("MLKEM"))
        //                    .count();
        //            long xdhCount = services.stream()
        //                    .filter(s -> s.getAlgorithm().contains("XDH") || s.getAlgorithm().contains("X25519"))
        //                    .count();
        //            LOG.info("BC Provider has " + mlkemCount + " ML-KEM/KEM related services");
        //            LOG.info("BC Provider has " + xdhCount + " XDH/X25519 related services");
        //        }
        //
        //        // Try to check if BouncyCastle TLS layer supports X25519MLKEM768
        //        LOG.info("Checking BouncyCastle TLS layer support for X25519MLKEM768:");
        //        try {
        //            Class<?> tlsUtilsClass = Class.forName("org.bouncycastle.tls.TlsUtils");
        //            Class<?> tlsCryptoClass = Class.forName("org.bouncycastle.tls.crypto.TlsCrypto");
        //            Class<?> jcaTlsCryptoProviderClass = Class.forName(
        //                    "org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider");
        //
        //            // Create a JcaTlsCrypto instance using the crypto provider
        //            Object cryptoProvider = jcaTlsCryptoProviderClass.getDeclaredConstructor().newInstance();
        //            java.lang.reflect.Method createMethod = jcaTlsCryptoProviderClass.getDeclaredMethod(
        //                    "create", java.security.SecureRandom.class);
        //            Object jcaTlsCrypto = createMethod.invoke(cryptoProvider, new java.security.SecureRandom());
        //
        //            // Call TlsUtils.isSupportedNamedGroup(crypto, X25519MLKEM768)
        //            java.lang.reflect.Method isSupportedMethod = tlsUtilsClass.getDeclaredMethod(
        //                    "isSupportedNamedGroup", tlsCryptoClass, int.class);
        //            isSupportedMethod.setAccessible(true);
        //            boolean supported = (Boolean) isSupportedMethod.invoke(null, jcaTlsCrypto, 0x11ec); // X25519MLKEM768 = 0x11ec
        //
        //            LOG.info("TlsUtils.isSupportedNamedGroup(crypto, X25519MLKEM768) = " + supported);
        //
        //            // Now check if we can get AlgorithmParameters for the hybrid components
        //            Class<?> namedGroupClass = Class.forName("org.bouncycastle.tls.NamedGroup");
        //            java.lang.reflect.Method getHybridFirstMethod = namedGroupClass.getDeclaredMethod(
        //                    "getHybridFirst", int.class);
        //            java.lang.reflect.Method getHybridSecondMethod = namedGroupClass.getDeclaredMethod(
        //                    "getHybridSecond", int.class);
        //            getHybridFirstMethod.setAccessible(true);
        //            getHybridSecondMethod.setAccessible(true);
        //
        //            int firstGroup = (Integer) getHybridFirstMethod.invoke(null, 0x11ec); // X25519
        //            int secondGroup = (Integer) getHybridSecondMethod.invoke(null, 0x11ec); // MLKEM768
        //
        //            LOG.info("X25519MLKEM768 hybrid components: first=" + firstGroup + " (0x" +
        //                    Integer.toHexString(firstGroup) + "), second=" + secondGroup +
        //                    " (0x" + Integer.toHexString(secondGroup) + ")");
        //
        //            // Try to get AlgorithmParameters for each component
        //            Class<?> jcaTlsCryptoClass = Class.forName(
        //                    "org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto");
        //            java.lang.reflect.Method getAlgorithmParametersMethod = jcaTlsCryptoClass.getDeclaredMethod(
        //                    "getNamedGroupAlgorithmParameters", int.class);
        //            getAlgorithmParametersMethod.setAccessible(true);
        //
        //            try {
        //                Object params1 = getAlgorithmParametersMethod.invoke(jcaTlsCrypto, firstGroup);
        //                LOG.info("AlgorithmParameters for first component (0x" +
        //                        Integer.toHexString(firstGroup) + "): " + (params1 != null ? "SUCCESS" : "null"));
        //            } catch (Exception e1) {
        //                LOG.warn("AlgorithmParameters for first component (0x" +
        //                        Integer.toHexString(firstGroup) + ") FAILED: " + e1.getCause());
        //            }
        //
        //            try {
        //                Object params2 = getAlgorithmParametersMethod.invoke(jcaTlsCrypto, secondGroup);
        //                LOG.info("AlgorithmParameters for second component (0x" +
        //                        Integer.toHexString(secondGroup) + "): " + (params2 != null ? "SUCCESS" : "null"));
        //            } catch (Exception e2) {
        //                LOG.warn("AlgorithmParameters for second component (0x" +
        //                        Integer.toHexString(secondGroup) + ") FAILED: " + e2.getCause());
        //            }
        //        } catch (Exception e) {
        //            LOG.warn("Could not check TLS layer support for X25519MLKEM768: " + e.getMessage(), e);
        //        }
        //
        //        // CRITICAL: Explicitly set named groups
        //        // The system property jdk.tls.namedGroups may not be automatically picked up
        //        // by BCJSSE in all scenarios, especially in native mode
        //        // Include fallback groups so handshake can succeed even if X25519MLKEM768 fails
        //        String configuredGroups = System.getProperty("jdk.tls.namedGroups", "X25519MLKEM768,x25519,secp256r1");
        //        try {
        //            String[] namedGroupsArray = configuredGroups.split(",");
        //            for (int i = 0; i < namedGroupsArray.length; i++) {
        //                namedGroupsArray[i] = namedGroupsArray[i].trim();
        //            }
        //            params.setNamedGroups(namedGroupsArray);
        //            LOG.info("Explicitly set named groups: " + Arrays.toString(namedGroupsArray));
        //
        //            // Verify they were set
        //            String[] verifyGroups = params.getNamedGroups();
        //            LOG.info("Named groups (after): " + (verifyGroups != null ? Arrays.toString(verifyGroups) : "null"));
        //        } catch (Exception e) {
        //            LOG.warn("Could not set named groups: " + e.getMessage(), e);
        //        }
        //
        //        LOG.info("=== SSL context created ===");

        return sslContext;
    }
}
