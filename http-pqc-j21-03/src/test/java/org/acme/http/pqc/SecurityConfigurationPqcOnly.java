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

import io.quarkus.arc.profile.IfBuildProfile;
import io.quarkus.runtime.StartupEvent;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import org.jboss.logging.Logger;

/**
 * Test-only SecurityConfiguration for X25519MLKEM768 ONLY (no fallback).
 * Only active when build profile is "pqc-only".
 */
@IfBuildProfile("pqc-only")
@ApplicationScoped
public class SecurityConfigurationPqcOnly {

    private static final Logger LOG = Logger.getLogger(SecurityConfigurationPqcOnly.class);

    @Priority(1000)
    void onStart(@Observes StartupEvent ev) {
        // Override with X25519MLKEM768 ONLY (no fallback)
        System.setProperty("jdk.tls.namedGroups", "X25519MLKEM768");
        LOG.info("TEST ALTERNATIVE: Configured TLS named groups for PQC: X25519MLKEM768 ONLY (no fallback)");
    }
}
