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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.core.util.KeyStoreUtil;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.listener.AbstractIdentityProviderMgtListener;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

/**
 * Identity Provider management listener for OpenID4VP authenticator.
 *
 * <p>This listener automatically provisions an Ed25519 (EdDSA) keypair into the
 * tenant's keystore under the alias {@value #OID4VP_EDDSA_ALIAS} whenever a new
 * Identity Provider that includes the {@code OpenID4VPAuthenticator} federated
 * authenticator configuration is created. The keypair is used for signing
 * OpenID4VP Authorization Request JWTs using the EdDSA algorithm.</p>
 *
 * <p>Key provisioning is performed lazily and idempotently: if the alias already
 * exists in the keystore the method returns immediately without any modification.</p>
 */
public class OpenID4VPIdPManagementListener extends AbstractIdentityProviderMgtListener {

    private static final Log LOG = LogFactory.getLog(OpenID4VPIdPManagementListener.class);

    /**
     * Suffix for the EdDSA signing key alias to distinguish it from the primary RSA key.
     * Aligned with org.wso2.carbon.core.util.KeyStoreUtil.TENANT_EDDSA_KEY_SUFFIX.
     */
    private static final String TENANT_EDDSA_KEY_SUFFIX = "_ed";

    /**
     * Name of the OpenID4VP federated authenticator as registered with the framework.
     */
    private static final String OID4VP_AUTHENTICATOR_NAME = "OpenID4VPAuthenticator";

    /**
     * Subject Distinguished Name used for the self-signed certificate wrapper.
     */
    private static final String CERT_SUBJECT_DN = "CN=oid4vp, OU=WSO2, O=Tenant, C=US";

    /**
     * JCA algorithm name for Ed25519 native keypair generation (Java 15+).
     */
    private static final String ALGORITHM_ED25519 = "Ed25519";

    /**
     * BouncyCastle signature algorithm identifier for EdDSA.
     */
    private static final String BC_SIGNER_ALGORITHM = "Ed25519";

    /**
     * Certificate validity period in milliseconds (10 years).
     */
    private static final long CERT_VALIDITY_MS = 10L * 365 * 24 * 60 * 60 * 1000;

    /**
     * Listener execution order: higher than framework defaults (which typically use 50–100).
     *
     * @return 110
     */
    @Override
    public int getDefaultOrderId() {

        return 110;
    }

    /**
     * Invoked after a new Identity Provider is successfully persisted.
     *
     * <p>If the created IdP includes the {@code OpenID4VPAuthenticator} federated
     * authenticator, this method ensures that an Ed25519 keypair is present in the
     * tenant keystore under the alias {@value #OID4VP_EDDSA_ALIAS}.</p>
     *
     * @param identityProvider The newly created {@link IdentityProvider}.
     * @param tenantDomain     The tenant domain in which the IdP was created.
     * @return {@code true} to allow the listener chain to continue.
     * @throws IdentityProviderManagementException Never thrown; exceptions are caught
     *                                             and logged to avoid disrupting IdP creation.
     */
    @Override
    public boolean doPostAddIdP(IdentityProvider identityProvider, String tenantDomain)
            throws IdentityProviderManagementException {

        if (!isOid4vpIdP(identityProvider)) {
            return true;
        }

        String alias = tenantDomain + TENANT_EDDSA_KEY_SUFFIX;
        LOG.info("OpenID4VP IdP detected for tenant [" + tenantDomain
                + "]. Checking for EdDSA keypair under alias '" + alias + "'.");

        try {
            provisionEdDsaKeyPairIfAbsent(tenantDomain, alias);
        } catch (Exception e) {
            // Log and swallow to avoid rolling back IdP creation for a key-provisioning failure.
            LOG.error("Failed to provision EdDSA keypair for tenant [" + tenantDomain
                    + "] with alias [" + alias + "]. The IdP was created but DID document signing may be unavailable.",
                    e);
        }

        return true;
    }

    /**
     * Checks whether the given identity provider contains the OpenID4VP federated authenticator.
     *
     * @param identityProvider The identity provider to inspect.
     * @return {@code true} if the authenticator named {@value #OID4VP_AUTHENTICATOR_NAME} is present.
     */
    private boolean isOid4vpIdP(IdentityProvider identityProvider) {

        if (identityProvider == null) {
            return false;
        }

        FederatedAuthenticatorConfig[] configs = identityProvider.getFederatedAuthenticatorConfigs();
        if (configs == null) {
            return false;
        }

        return Arrays.stream(configs)
                .anyMatch(config -> OID4VP_AUTHENTICATOR_NAME.equals(config.getName()));
    }

    /**
     * Provisions an Ed25519 keypair into the tenant keystore if the alias does not already exist.
     *
     * <p>Steps:
     * <ol>
     *   <li>Resolve the tenant ID from the tenant domain.</li>
     *   <li>Retrieve the tenant's {@link KeyStore} via {@link KeyStoreManager}.</li>
     *   <li>Return early if the alias {@value #OID4VP_EDDSA_ALIAS} already exists.</li>
     *   <li>Generate a fresh Ed25519 {@link KeyPair} using the native Java 21 provider.</li>
     *   <li>Wrap the public key in a BouncyCastle self-signed X.509 v3 certificate.</li>
     *   <li>Store the private key and certificate chain in the keystore and persist via
     *       {@link KeyStoreManager#updateKeyStore(String, KeyStore)}.</li>
     * </ol>
     * </p>
     *
     * @param tenantDomain The tenant domain whose keystore should be updated.
     * @param alias        The alias to use for the EdDSA keypair.
     * @throws Exception If any cryptographic or keystore operation fails.
     */
    private void provisionEdDsaKeyPairIfAbsent(String tenantDomain, String alias) throws Exception {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
        String keyStoreName = resolveKeyStoreName(tenantDomain);
        KeyStore keyStore = keyStoreManager.getKeyStore(keyStoreName);

        if (keyStore.containsAlias(alias)) {
            LOG.info("EdDSA alias '" + alias + "' already exists in the keystore for tenant ["
                    + tenantDomain + "]. Skipping key generation.");
            return;
        }

        LOG.info("Generating Ed25519 keypair for tenant [" + tenantDomain + "] under alias '"
                + alias + "'.");

        KeyPair keyPair = generateEd25519KeyPair();
        X509Certificate selfSignedCert = buildSelfSignedCertificate(keyPair);

        char[] keyPassword = keyStoreManager.getPrivateKeyPassword(keyStoreName);
        try {
            keyStore.setKeyEntry(
                    alias,
                    keyPair.getPrivate(),
                    keyPassword,
                    new Certificate[]{selfSignedCert});

            keyStoreManager.updateKeyStore(keyStoreName, keyStore);
        } finally {
            if (keyPassword != null) {
                Arrays.fill(keyPassword, '\0');
            }
        }

        LOG.info("Ed25519 keypair successfully provisioned for tenant [" + tenantDomain
                + "] under alias '" + alias + "'.");
    }

    /**
     * Generates a fresh Ed25519 {@link KeyPair} using the default JCA provider.
     *
     * <p>Ed25519 is natively supported from Java 15 onwards and does not require
     * BouncyCastle for key generation.</p>
     *
     * @return A new Ed25519 {@link KeyPair}.
     * @throws NoSuchAlgorithmException If the Ed25519 algorithm is not available.
     */
    private KeyPair generateEd25519KeyPair() throws NoSuchAlgorithmException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM_ED25519);
        return kpg.generateKeyPair();
    }

    /**
     * Builds a self-signed X.509 v3 certificate for the given Ed25519 keypair.
     *
     * <p>BouncyCastle is used for certificate construction because the JDK does not
     * expose a public API for generating X.509 certificates. The resulting certificate
     * acts as a wrapper required by the PKCS12/JKS keystore format when storing a
     * private key entry.</p>
     *
     * @param keyPair The Ed25519 keypair to wrap.
     * @return A self-signed {@link X509Certificate}.
     * @throws OperatorCreationException If the content signer cannot be created.
     * @throws CertificateException      If certificate conversion fails.
     */
    private X509Certificate buildSelfSignedCertificate(KeyPair keyPair)
            throws OperatorCreationException, CertificateException {

        X500Name subjectDN = new X500Name(CERT_SUBJECT_DN);
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + CERT_VALIDITY_MS);

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subjectDN,
                serialNumber,
                notBefore,
                notAfter,
                subjectDN,
                keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder(BC_SIGNER_ALGORITHM)
                .build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);

        return new JcaX509CertificateConverter()
                .getCertificate(certHolder);
    }

    /**
     * Resolves the expected keystore name for the given tenant domain.
     *
     * <p>WSO2 IS uses the convention {@code <tenantDomain>.jks} for tenant keystores.
     * The super-tenant uses a different mechanism, but this listener only targets
     * newly created federated IdPs which are always tenant-scoped.</p>
     *
     * @param tenantDomain The tenant domain.
     * @return The keystore resource name (e.g., {@code "example.com.jks"}).
     */
    private String resolveKeyStoreName(String tenantDomain) {

        if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            return KeyStoreUtil.getKeyStoreFileName(null);
        }
        return tenantDomain + ".jks";
    }
}
