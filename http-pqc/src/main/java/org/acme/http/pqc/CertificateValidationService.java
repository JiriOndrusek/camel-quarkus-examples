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

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

import jakarta.enterprise.context.ApplicationScoped;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service for validating Chimera hybrid certificates.
 * Validates both RSA and Dilithium3 signatures.
 */
@ApplicationScoped
public class CertificateValidationService {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateValidationService.class);

    // Extension OIDs for Chimera format
    private static final ASN1ObjectIdentifier OID_SUBJECT_ALT_PUBLIC_KEY_INFO = new ASN1ObjectIdentifier(
            "2.5.29.72");
    private static final ASN1ObjectIdentifier OID_ALT_SIGNATURE_VALUE = new ASN1ObjectIdentifier("2.5.29.74");

    /**
     * Validates a hybrid certificate by checking both RSA and Dilithium3 signatures.
     *
     * @param  cert The certificate to validate
     * @return      ValidationResult with details of RSA and Dilithium3 validation
     */
    public ValidationResult validateHybridCertificate(X509Certificate cert) {
        LOG.info("Validating hybrid certificate for subject: {}", cert.getSubjectX500Principal());

        boolean rsaValid = false;
        boolean dilithiumValid = false;
        String message;

        try {
            // Verify RSA signature (standard X.509 verification)
            rsaValid = verifyRsaSignature(cert);

            if (!rsaValid) {
                message = "RSA signature validation failed";
                LOG.warn(message);
                return new ValidationResult(false, false, message);
            }

            LOG.info("✓ RSA signature verified");

            // Extract and verify Dilithium3 signature
            PublicKey dilithiumPublicKey = extractDilithiumPublicKey(cert);
            if (dilithiumPublicKey == null) {
                message = "PQC public key extension missing (OID 2.5.29.72)";
                LOG.warn(message);
                return new ValidationResult(true, false, message);
            }

            byte[] dilithiumSignature = extractDilithiumSignature(cert);
            if (dilithiumSignature == null) {
                message = "PQC signature extension missing (OID 2.5.29.74)";
                LOG.warn(message);
                return new ValidationResult(true, false, message);
            }

            dilithiumValid = verifyDilithiumSignature(cert, dilithiumPublicKey, dilithiumSignature);

            if (!dilithiumValid) {
                message = "Dilithium3 signature validation failed";
                LOG.warn(message);
                return new ValidationResult(true, false, message);
            }

            LOG.info("✓ Dilithium3 signature verified");

            message = "Both RSA and Dilithium3 signatures validated successfully";
            LOG.info(message);
            return new ValidationResult(true, true, message);

        } catch (Exception e) {
            message = "Certificate validation error: " + e.getMessage();
            LOG.error(message, e);
            return new ValidationResult(rsaValid, false, message);
        }
    }

    /**
     * Verifies the RSA signature using standard X.509 verification.
     */
    private boolean verifyRsaSignature(X509Certificate cert) {
        try {
            // Self-signed certificate - verify with its own public key
            cert.verify(cert.getPublicKey());
            return true;
        } catch (Exception e) {
            LOG.error("RSA signature verification failed", e);
            return false;
        }
    }

    /**
     * Extracts the Dilithium3 public key from the altSubjectPublicKeyInfo extension.
     */
    private PublicKey extractDilithiumPublicKey(X509Certificate cert) {
        try {
            byte[] extensionValue = cert.getExtensionValue(OID_SUBJECT_ALT_PUBLIC_KEY_INFO.getId());
            if (extensionValue == null) {
                return null;
            }

            // Extension value is wrapped in OCTET STRING
            ASN1Primitive primitive = ASN1Primitive.fromByteArray(extensionValue);
            byte[] octets = ((ASN1OctetString) primitive).getOctets();

            // Parse SubjectPublicKeyInfo
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(octets);

            // Convert to PublicKey using X509EncodedKeySpec
            KeyFactory keyFactory = KeyFactory.getInstance("Dilithium3", "BC");
            return keyFactory.generatePublic(new X509EncodedKeySpec(spki.getEncoded()));

        } catch (Exception e) {
            LOG.error("Failed to extract Dilithium3 public key", e);
            return null;
        }
    }

    /**
     * Extracts the Dilithium3 signature from the altSignatureValue extension.
     */
    private byte[] extractDilithiumSignature(X509Certificate cert) {
        try {
            byte[] extensionValue = cert.getExtensionValue(OID_ALT_SIGNATURE_VALUE.getId());
            if (extensionValue == null) {
                return null;
            }

            // Extension value is wrapped in OCTET STRING
            ASN1Primitive primitive = ASN1Primitive.fromByteArray(extensionValue);
            byte[] octets = ((ASN1OctetString) primitive).getOctets();

            // Parse as BIT STRING
            ASN1BitString bitString = ASN1BitString.getInstance(octets);
            return bitString.getBytes();

        } catch (Exception e) {
            LOG.error("Failed to extract Dilithium3 signature", e);
            return null;
        }
    }

    /**
     * Verifies the Dilithium3 signature.
     */
    private boolean verifyDilithiumSignature(X509Certificate cert, PublicKey pqcKey, byte[] signature) {
        try {
            Signature dilithiumVerify = Signature.getInstance("Dilithium3", "BC");
            dilithiumVerify.initVerify(pqcKey);
            dilithiumVerify.update(cert.getSubjectX500Principal().getEncoded());
            return dilithiumVerify.verify(signature);
        } catch (Exception e) {
            LOG.error("Dilithium3 signature verification failed", e);
            return false;
        }
    }
}
