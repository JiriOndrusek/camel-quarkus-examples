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
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Named;
import org.apache.camel.support.jsse.KeyManagersParameters;
import org.apache.camel.support.jsse.KeyStoreParameters;
import org.apache.camel.support.jsse.SSLContextParameters;
import org.apache.camel.support.jsse.SSLContextServerParameters;
import org.apache.camel.support.jsse.TrustManagersParameters;
import org.jboss.logging.Logger;

/**
 * Configures Camel's global SSL context to use BouncyCastle JSSE provider.
 * This simulates the approach from oscerd/camel-pqc-tls example.
 *
 * Note: In Quarkus, platform-http endpoints use the Quarkus HTTP server (quarkus.http.ssl.*).
 * This SSL context is used by other Camel components (http, netty-http, etc.) that support SSL.
 */
@ApplicationScoped
public class CamelSslConfiguration {

    private static final Logger LOG = Logger.getLogger(CamelSslConfiguration.class);

    /**
     * Produces global SSL context parameters for Camel.
     * Configured to use BCJSSE provider with PQC support.
     */
    @Produces
    @ApplicationScoped
    @Named("sslContextParameters")
    public SSLContextParameters createSslContextParameters() {
        LOG.info("Creating Camel SSL context with BCJSSE provider for PQC support");

        // Server keystore configuration
        KeyStoreParameters serverKeystore = new KeyStoreParameters();
        serverKeystore.setResource("target/certs/server-keystore.p12");
        serverKeystore.setPassword("changeit");
        serverKeystore.setType("PKCS12");
        serverKeystore.setProvider("BC");

        KeyManagersParameters keyManagers = new KeyManagersParameters();
        keyManagers.setKeyStore(serverKeystore);
        keyManagers.setKeyPassword("changeit");
        keyManagers.setProvider("BCJSSE");

        // Server truststore configuration
        KeyStoreParameters serverTruststore = new KeyStoreParameters();
        serverTruststore.setResource("target/certs/server-truststore.p12");
        serverTruststore.setPassword("changeit");
        serverTruststore.setType("PKCS12");
        serverTruststore.setProvider("BC");

        TrustManagersParameters trustManagers = new TrustManagersParameters();
        trustManagers.setKeyStore(serverTruststore);
        trustManagers.setProvider("BCJSSE");

        // Server parameters for TLS 1.3
        SSLContextServerParameters serverParameters = new SSLContextServerParameters();
        serverParameters.setClientAuthentication("REQUIRE");

        // Create SSL context
        SSLContextParameters sslContext = new SSLContextParameters();
        sslContext.setKeyManagers(keyManagers);
        sslContext.setTrustManagers(trustManagers);
        sslContext.setServerParameters(serverParameters);
        sslContext.setProvider("BCJSSE");
        sslContext.setSecureSocketProtocol("TLSv1.3");

        LOG.info("Camel SSL context configured with BCJSSE provider, TLS 1.3, and PQC-ready certificates");

        return sslContext;
    }
}
