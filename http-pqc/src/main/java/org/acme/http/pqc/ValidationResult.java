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

/**
 * Result of hybrid certificate validation.
 * Both RSA and Dilithium3 signatures must be valid for overall validation to succeed.
 */
public class ValidationResult {
    private final boolean rsaValid;
    private final boolean dilithiumValid;
    private final String message;

    public ValidationResult(boolean rsaValid, boolean dilithiumValid, String message) {
        this.rsaValid = rsaValid;
        this.dilithiumValid = dilithiumValid;
        this.message = message;
    }

    public boolean isRsaValid() {
        return rsaValid;
    }

    public boolean isDilithiumValid() {
        return dilithiumValid;
    }

    /**
     * Both RSA and Dilithium3 signatures must be valid.
     */
    public boolean isOverallValid() {
        return rsaValid && dilithiumValid;
    }

    public String getMessage() {
        return message;
    }
}
