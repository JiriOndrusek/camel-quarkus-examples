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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service demonstrating ML-DSA (Dilithium) post-quantum digital signatures.
 * ML-DSA is FIPS 204, formerly known as CRYSTALS-Dilithium.
 */
@ApplicationScoped
public class PqcSignatureService {

    private static final Logger LOG = LoggerFactory.getLogger(PqcSignatureService.class);
    // Using Dilithium3 (equivalent to ML-DSA-65 / FIPS 204 Level 3)
    // BouncyCastle 1.78.1 uses legacy names; ML-DSA names require BC 1.79+
    private static final String PQC_SIGNATURE_ALGORITHM = "Dilithium3";
    private static final String PROVIDER = "BC";

    private KeyPair mlDsaKeyPair;

    @PostConstruct
    public void init() {
        try {
            LOG.info("Generating Dilithium3 (ML-DSA-65 equivalent) keypair for post-quantum signatures...");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(PQC_SIGNATURE_ALGORITHM, PROVIDER);
            mlDsaKeyPair = kpg.generateKeyPair();
            LOG.info("Dilithium3 keypair generated successfully. Public key size: {} bytes",
                    mlDsaKeyPair.getPublic().getEncoded().length);
        } catch (Exception e) {
            LOG.error("Failed to initialize Dilithium keypair", e);
            throw new RuntimeException("PQC signature initialization failed", e);
        }
    }

    /**
     * Signs a message using ML-DSA-65 (post-quantum signature algorithm).
     *
     * @param  message the message to sign
     * @return         base64-encoded signature
     */
    public String signMessage(String message) {
        try {
            Signature signature = Signature.getInstance(PQC_SIGNATURE_ALGORITHM, PROVIDER);
            signature.initSign(mlDsaKeyPair.getPrivate());
            signature.update(message.getBytes());
            byte[] signatureBytes = signature.sign();
            LOG.debug("Message signed with Dilithium3. Signature size: {} bytes", signatureBytes.length);
            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (Exception e) {
            LOG.error("Failed to sign message with Dilithium", e);
            throw new RuntimeException("Dilithium signature failed", e);
        }
    }

    /**
     * Verifies a ML-DSA-65 signature.
     *
     * @param  message   the original message
     * @param  signature the base64-encoded signature
     * @return           true if signature is valid
     */
    public boolean verifySignature(String message, String signature) {
        try {
            Signature sig = Signature.getInstance(PQC_SIGNATURE_ALGORITHM, PROVIDER);
            sig.initVerify(mlDsaKeyPair.getPublic());
            sig.update(message.getBytes());
            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            boolean valid = sig.verify(signatureBytes);
            LOG.debug("Dilithium3 signature verification: {}", valid ? "VALID" : "INVALID");
            return valid;
        } catch (Exception e) {
            LOG.error("Failed to verify Dilithium signature", e);
            return false;
        }
    }

    public PublicKey getPublicKey() {
        return mlDsaKeyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return mlDsaKeyPair.getPrivate();
    }

    public String getAlgorithm() {
        return PQC_SIGNATURE_ALGORITHM;
    }
}
