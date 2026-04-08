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

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for generating and persisting Chimera hybrid certificates.
 * These certificates combine classical RSA with post-quantum Dilithium3 signatures
 * using X.509 extensions as specified in the BouncyCastle PQC Almanac.
 */
public class HybridCertificateGenerator {

    private static final Logger LOG = LoggerFactory.getLogger(HybridCertificateGenerator.class);

    // Extension OIDs for Chimera format (from X.509 standards)
    private static final ASN1ObjectIdentifier OID_SUBJECT_ALT_PUBLIC_KEY_INFO = new ASN1ObjectIdentifier(
            "2.5.29.72");
    private static final ASN1ObjectIdentifier OID_ALT_SIGNATURE_ALGORITHM = new ASN1ObjectIdentifier("2.5.29.73");
    private static final ASN1ObjectIdentifier OID_ALT_SIGNATURE_VALUE = new ASN1ObjectIdentifier("2.5.29.74");

    private static final String KEYSTORE_PASSWORD = "changeit";
    private static final String KEYSTORES_DIR = "src/main/resources/keystores";

    /**
     * Certificate data holder for keypairs and certificates.
     */
    public static class CertificateData {
        public final KeyPair rsaKeyPair;
        public final KeyPair dilithiumKeyPair;
        public final X509Certificate certificate;

        public CertificateData(KeyPair rsaKeyPair, KeyPair dilithiumKeyPair, X509Certificate certificate) {
            this.rsaKeyPair = rsaKeyPair;
            this.dilithiumKeyPair = dilithiumKeyPair;
            this.certificate = certificate;
        }
    }

    /**
     * Generates a Chimera hybrid certificate combining RSA and Dilithium3.
     *
     * @param  commonName          The CN for the certificate subject
     * @param  includeAltSignature Whether to include the Dilithium3 alternative signature
     * @return                     CertificateData containing keypairs and certificate
     */
    public static CertificateData generateChimeraCertificate(String commonName, boolean includeAltSignature)
            throws Exception {
        LOG.info("Generating Chimera hybrid certificate for CN={}, includeAltSignature={}",
                commonName, includeAltSignature);

        // Generate RSA keypair (classical algorithm)
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(2048, new SecureRandom());
        KeyPair rsaKeyPair = rsaKpg.generateKeyPair();

        // Generate Dilithium3 keypair (PQC algorithm)
        KeyPairGenerator dilithiumKpg = KeyPairGenerator.getInstance("Dilithium3", "BC");
        KeyPair dilithiumKeyPair = dilithiumKpg.generateKeyPair();

        // Build certificate
        X500Name issuer = new X500Name("CN=PQC Hybrid CA,O=Apache Camel Quarkus,C=US");
        X500Name subject = new X500Name("CN=" + commonName + ",O=Apache Camel Quarkus,C=US");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000); // 1 year

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                subject,
                rsaKeyPair.getPublic());

        if (includeAltSignature) {
            // Add Dilithium3 alternative public key (Chimera extension)
            SubjectPublicKeyInfo dilithiumPubKeyInfo = SubjectPublicKeyInfo
                    .getInstance(dilithiumKeyPair.getPublic().getEncoded());
            certBuilder.addExtension(OID_SUBJECT_ALT_PUBLIC_KEY_INFO, false, dilithiumPubKeyInfo);

            // Add alternative signature algorithm (Chimera extension)
            AlgorithmIdentifier dilithiumSigAlg = new AlgorithmIdentifier(
                    new ASN1ObjectIdentifier("1.3.6.1.4.1.2.267.7.6.5")); // Dilithium3 OID
            certBuilder.addExtension(OID_ALT_SIGNATURE_ALGORITHM, false, dilithiumSigAlg);

            // Generate Dilithium3 alternative signature (Chimera extension)
            Signature dilithiumSig = Signature.getInstance("Dilithium3", "BC");
            dilithiumSig.initSign(dilithiumKeyPair.getPrivate());
            dilithiumSig.update(subject.getEncoded()); // Sign subject DN as per Chimera spec
            byte[] dilithiumSignature = dilithiumSig.sign();
            certBuilder.addExtension(OID_ALT_SIGNATURE_VALUE, false, new DERBitString(dilithiumSignature));

            LOG.info("✓ Dilithium3 extensions added to certificate");
        }

        // Sign with RSA (primary signature)
        ContentSigner rsaSigner = new JcaContentSignerBuilder("SHA256withRSA").build(rsaKeyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(rsaSigner);

        // Convert to X509Certificate
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certHolder);

        LOG.info("✓ Chimera certificate generated successfully for CN={}", commonName);

        return new CertificateData(rsaKeyPair, dilithiumKeyPair, certificate);
    }

    /**
     * Generates server hybrid keystore with RSA + Dilithium3 certificate.
     */
    public static void generateServerKeystore() throws Exception {
        LOG.info("Generating server hybrid keystore...");

        CertificateData serverCert = generateChimeraCertificate("localhost", true);

        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(null, null);
        keyStore.setKeyEntry("server",
                serverCert.rsaKeyPair.getPrivate(),
                KEYSTORE_PASSWORD.toCharArray(),
                new X509Certificate[] { serverCert.certificate });

        String path = KEYSTORES_DIR + "/server-hybrid-keystore.p12";
        saveKeyStore(keyStore, path, KEYSTORE_PASSWORD);

        // Also create server truststore (for validating client certificates)
        KeyStore trustStore = KeyStore.getInstance("PKCS12", "BC");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("server-ca", serverCert.certificate);

        String trustPath = KEYSTORES_DIR + "/server-hybrid-truststore.p12";
        saveKeyStore(trustStore, trustPath, KEYSTORE_PASSWORD);

        LOG.info("✓ Server hybrid keystore created: {}", path);
        LOG.info("✓ Server hybrid truststore created: {}", trustPath);
    }

    /**
     * Generates client hybrid keystore with RSA + Dilithium3 certificate.
     */
    public static void generateClientHybridKeystore() throws Exception {
        LOG.info("Generating client hybrid keystore...");

        CertificateData clientCert = generateChimeraCertificate("client-hybrid", true);

        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(null, null);
        keyStore.setKeyEntry("client",
                clientCert.rsaKeyPair.getPrivate(),
                KEYSTORE_PASSWORD.toCharArray(),
                new X509Certificate[] { clientCert.certificate });

        String path = KEYSTORES_DIR + "/client-hybrid-keystore.p12";
        saveKeyStore(keyStore, path, KEYSTORE_PASSWORD);

        LOG.info("✓ Client hybrid keystore created: {}", path);
    }

    /**
     * Generates client RSA-only keystore (no PQC extensions - for failure test).
     */
    public static void generateClientRsaOnlyKeystore() throws Exception {
        LOG.info("Generating client RSA-only keystore...");

        CertificateData clientCert = generateChimeraCertificate("client-rsa-only", false);

        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(null, null);
        keyStore.setKeyEntry("client",
                clientCert.rsaKeyPair.getPrivate(),
                KEYSTORE_PASSWORD.toCharArray(),
                new X509Certificate[] { clientCert.certificate });

        String path = KEYSTORES_DIR + "/client-rsa-only-keystore.p12";
        saveKeyStore(keyStore, path, KEYSTORE_PASSWORD);

        LOG.info("✓ Client RSA-only keystore created: {}", path);
    }

    /**
     * Saves a KeyStore to disk.
     */
    public static void saveKeyStore(KeyStore keyStore, String path, String password) throws Exception {
        Path dirPath = Paths.get(path).getParent();
        if (!Files.exists(dirPath)) {
            Files.createDirectories(dirPath);
            LOG.info("Created directory: {}", dirPath);
        }

        try (FileOutputStream fos = new FileOutputStream(path)) {
            keyStore.store(fos, password.toCharArray());
        }
    }

    /**
     * Checks if a keystore file exists at the given path.
     */
    public static boolean keystoreExists(String path) {
        return Files.exists(Paths.get(path));
    }
}
