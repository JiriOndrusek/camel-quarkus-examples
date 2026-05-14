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

import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;

import io.quarkus.runtime.annotations.RegisterForReflection;

/**
 * Custom Security Provider that registers "DEFAULT" SecureRandom algorithm.
 * This is needed for GraalVM native images where BouncyCastle JSSE attempts
 * to call SecureRandom.getInstance("DEFAULT") but no provider registers this algorithm.
 */
@RegisterForReflection
public class DefaultSecureRandomProvider extends Provider {

    public DefaultSecureRandomProvider() {
        super("DefaultSecureRandom", "1.0", "Provider for DEFAULT SecureRandom algorithm");

        // Register DEFAULT SecureRandom algorithm
        put("SecureRandom.DEFAULT", DefaultSecureRandomSpi.class.getName());
    }

    /**
     * SecureRandomSpi implementation that delegates to a platform-specific SecureRandom.
     */
    @RegisterForReflection
    public static class DefaultSecureRandomSpi extends SecureRandomSpi {

        private final SecureRandom delegate;

        public DefaultSecureRandomSpi() {
            try {
                // Try platform-specific implementations to avoid recursion
                // (don't use new SecureRandom() as it might try to get DEFAULT)
                SecureRandom sr = null;
                try {
                    // Try NativePRNG (available on Linux/Unix)
                    sr = SecureRandom.getInstance("NativePRNG");
                } catch (Exception e) {
                    try {
                        // Try SHA1PRNG (widely available)
                        sr = SecureRandom.getInstance("SHA1PRNG");
                    } catch (Exception e2) {
                        // Last resort: try to get from SUN provider explicitly
                        sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
                    }
                }
                this.delegate = sr;
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize DEFAULT SecureRandom", e);
            }
        }

        @Override
        protected void engineSetSeed(byte[] seed) {
            delegate.setSeed(seed);
        }

        @Override
        protected void engineNextBytes(byte[] bytes) {
            delegate.nextBytes(bytes);
        }

        @Override
        protected byte[] engineGenerateSeed(int numBytes) {
            return delegate.generateSeed(numBytes);
        }
    }
}
