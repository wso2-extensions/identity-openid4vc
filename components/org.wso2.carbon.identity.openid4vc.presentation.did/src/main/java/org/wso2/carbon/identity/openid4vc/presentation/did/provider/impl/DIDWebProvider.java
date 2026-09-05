/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vc.presentation.did.provider.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import com.nimbusds.jose.util.Base64URL;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.did.model.DIDDocument;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.DIDProvider;
import org.wso2.carbon.identity.openid4vc.presentation.did.util.Base58;
import org.wso2.carbon.identity.openid4vc.presentation.did.util.Constraints;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.interfaces.EdECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

/**
 * DID Provider implementation for 'did:web' method.
 * Supports RSA (default via KeyStore), EdDSA and ES256 (via DIDKeyManager).
 */
public class DIDWebProvider implements DIDProvider {

    /**
     * Get the provider name.
     *
     * @return The provider name.
     */
    @Override
    public String getName() {

        return Constraints.METHOD_WEB;
    }

    /**
     * Get the DID identifier for the given tenant and base URL.
     *
     * @param tenantId The tenant ID.
     * @param baseUrl  The base URL.
     * @return The DID identifier.
     * @throws VPException If DID generation fails.
     */
    @Override
    public String getDID(int tenantId, String baseUrl) throws VPException {

        if (StringUtils.isBlank(baseUrl)) {
            throw new VPException("Base URL is required for did:web generation");
        }

        try {
            URI uri = URI.create(baseUrl);
            String host = uri.getHost();
            if (StringUtils.isBlank(host)) {
                throw new VPException("Invalid base URL: host is missing for URL: " + baseUrl);
            }

            StringBuilder didDomain = new StringBuilder(host);
            int port = uri.getPort();
            if (port != -1) {
                // According to did:web spec, port colon is percent-encoded as %3A
                didDomain.append("%3A").append(port);
            }

            String path = uri.getPath();
            if (StringUtils.isNotBlank(path) && !"/".equals(path)) {
                String normalizedPath = path;
                // Remove leading and trailing slashes
                if (normalizedPath.startsWith("/")) {
                    normalizedPath = normalizedPath.substring(1);
                }
                if (normalizedPath.endsWith("/")) {
                    normalizedPath = normalizedPath.substring(0, normalizedPath.length() - 1);
                }
                if (StringUtils.isNotBlank(normalizedPath)) {
                    // According to did:web spec, path slashes are replaced with colons
                    didDomain.append(":").append(normalizedPath.replace("/", ":"));
                }
            }
            return Constraints.DID_WEB_PREFIX + didDomain.toString();
        } catch (Exception e) {
            throw new VPException("Error generating did:web from base URL: " + baseUrl, e);
        }
    }

    /**
     * Get the signing key ID for the given tenant and base URL.
     *
     * @param tenantId The tenant ID.
     * @param baseUrl  The base URL.
     * @return The signing key ID.
     * @throws VPException If key ID generation fails.
     */
    @Override
    public String getSigningKeyId(int tenantId, String baseUrl) throws VPException {

        return getDID(tenantId, baseUrl) + Constraints.ED25519_KEY_ID_FRAGMENT;
    }

    /**
     * Get the signing algorithm.
     *
     * @return The signing algorithm.
     */
    @Override
    public JWSAlgorithm getSigningAlgorithm() {

        return JWSAlgorithm.EdDSA;
    }

    /**
     * Get the signer for the given tenant.
     *
     * @param tenantId The tenant ID.
     * @return The JWSSigner instance.
     * @throws VPException If signer creation fails.
     */
    @Override
    public JWSSigner getSigner(int tenantId) throws VPException {

        try {
            // Use KeyStore for EdDSA keys
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
            String edKeyAlias = getEdDSAKeyAlias(tenantId);
            PrivateKey privateKey = keyStoreManager.getDefaultPrivateKey(edKeyAlias);

            return new JcaEd25519Signer(privateKey);
        } catch (Exception e) {
            throw new VPException("Error creating signer for did:web", e);
        }
    }

    /**
     * Get the DID document for the given tenant and base URL.
     *
     * @param tenantId The tenant ID.
     * @param baseUrl  The base URL.
     * @return The DID document.
     * @throws VPException If DID document generation fails.
     */
    @Override
    public DIDDocument getDIDDocument(int tenantId, String baseUrl) throws VPException {

        try {
            String did = getDID(tenantId, baseUrl);

            DIDDocument didDocument = new DIDDocument();
            didDocument.setId(did);

            // Add Standard Contexts
            List<String> contexts = new ArrayList<>();
            contexts.add(Constraints.DID_V1_CONTEXT);
            contexts.add(Constraints.ED25519_2020_CONTEXT);
            didDocument.setContext(contexts);

            List<DIDDocument.VerificationMethod> verificationMethods = new ArrayList<>();
            List<String> relationships = new ArrayList<>();

            try {
                String keyId = getSigningKeyId(tenantId, baseUrl);

                // Use KeyStore for EdDSA keys
                KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
                String edKeyAlias = getEdDSAKeyAlias(tenantId);
                PublicKey publicKey = keyStoreManager.getDefaultPublicKey(edKeyAlias);

                DIDDocument.VerificationMethod vm = new DIDDocument.VerificationMethod();
                vm.setId(keyId);
                vm.setController(did);
                vm.setType(Constraints.ED25519_VERIFICATION_KEY_2020);

                // Convert PublicKey to multibase format
                String multibase = convertPublicKeyToMultibase(publicKey);
                vm.setPublicKeyMultibase(multibase);

                verificationMethods.add(vm);
                relationships.add(keyId);

            } catch (Exception e) {
                LogFactory.getLog(DIDWebProvider.class)
                        .error("Error while generating verification method for did:web", e);
            }
            didDocument.setVerificationMethod(verificationMethods);
            didDocument.setAuthentication(relationships);
            didDocument.setAssertionMethod(relationships);

            return didDocument;

        } catch (Exception e) {
            throw new VPException("Error generating DID Document for did:web", e);
        }
    }

    /**
     * Convert PublicKey to multibase format for DID document.
     *
     * @param publicKey The public key from KeyStore.
     * @return Multibase encoded string.
     * @throws Exception If conversion fails.
     */
    private String convertPublicKeyToMultibase(PublicKey publicKey) throws Exception {

        byte[] publicKeyBytes = publicKey.getEncoded();

        // Extract raw Ed25519 public key (32 bytes at the end)
        byte[] rawPublicKey = Arrays.copyOfRange(publicKeyBytes,
                publicKeyBytes.length - 32, publicKeyBytes.length);

        // Prepend multicodec prefix for Ed25519-pub (0xed01)
        byte[] multicodecKey = new byte[34];
        multicodecKey[0] = (byte) 0xed;
        multicodecKey[1] = (byte) 0x01;
        System.arraycopy(rawPublicKey, 0, multicodecKey, 2, 32);

        return "z" + Base58.encode(multicodecKey);
    }

    /**
     * Get the EdDSA key alias for the given tenant.
     *
     * @param tenantId The tenant ID.
     * @return The key alias.
     * @throws VPException If retrieval fails.
     */
    private String getEdDSAKeyAlias(int tenantId) throws VPException {

        try {
            String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            if (tenantId != MultitenantConstants.SUPER_TENANT_ID) {
                tenantDomain = PrivilegedCarbonContext
                        .getThreadLocalCarbonContext().getTenantDomain();
            }

            KeyStore keystore = IdentityKeyStoreResolver.getInstance()
                    .getKeyStore(tenantDomain, IdentityKeyStoreResolverConstants
                            .InboundProtocol.OAUTH);

            if (keystore != null) {
                Enumeration<String> enumeration = keystore.aliases();
                while (enumeration.hasMoreElements()) {
                    String alias = enumeration.nextElement();
                    if (keystore.isKeyEntry(alias)) {
                        Certificate cert = keystore
                                .getCertificate(alias);
                        if (cert != null && cert.getPublicKey() instanceof
                                EdECPublicKey) {
                            return alias;
                        }
                    }
                }
            }
        } catch (Exception e) {
            throw new VPException(
                    "Failed to retrieve EdDSA key alias for tenant: " +
                            tenantId, e);
        }
        throw new VPException(
                "No EdDSA key found in the keystore for tenant: " + tenantId);
    }

    /**
     * Ed25519 signer implementation based on the JCA Signature API.
     */
    private static final class JcaEd25519Signer extends BaseJWSProvider implements JWSSigner {

        private final PrivateKey privateKey;

        private JcaEd25519Signer(PrivateKey privateKey) {

            super(Collections.singleton(JWSAlgorithm.EdDSA));
            this.privateKey = privateKey;
        }

        @Override
        public Base64URL sign(com.nimbusds.jose.JWSHeader jwsHeader, byte[] signingInput)
                throws JOSEException {

            if (!JWSAlgorithm.EdDSA.equals(jwsHeader.getAlgorithm())) {
                throw new JOSEException("Unsupported JWS algorithm: " + jwsHeader.getAlgorithm());
            }

            try {
                Signature signature = Signature.getInstance("Ed25519");
                signature.initSign(privateKey);
                signature.update(signingInput);
                return Base64URL.encode(signature.sign());
            } catch (GeneralSecurityException e) {
                throw new JOSEException("Error signing EdDSA payload", e);
            }
        }
    }
}
