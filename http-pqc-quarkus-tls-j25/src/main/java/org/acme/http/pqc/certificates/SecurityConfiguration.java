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
package org.acme.http.pqc.certificates;

import io.quarkus.arc.DefaultBean;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import org.jboss.logging.Logger;

/**
 * Startup hook for PQC TLS example.
 *
 * Certificates are generated during the Maven build (exec-maven-plugin, process-classes phase)
 * because the Quarkus TLS Registry validates keystores during RUNTIME_INIT, before StartupEvent.
 *
 * Unlike the JDK 21 example, no BouncyCastle JSSE provider registration or
 * system property configuration is needed — JDK 25+ supports PQC key exchange
 * (X25519MLKEM768) natively via SunJSSE. PQC is configured entirely through
 * the Quarkus TLS Registry (quarkus.tls.key-exchange-protocols).
 */
@DefaultBean
@ApplicationScoped
public class SecurityConfiguration {

    private static final Logger LOG = Logger.getLogger(SecurityConfiguration.class);

    void onStart(@Observes StartupEvent ev) {
        LOG.info("PQC TLS example started — using Quarkus TLS Registry with JDK 25+ native SunJSSE");
    }
}
