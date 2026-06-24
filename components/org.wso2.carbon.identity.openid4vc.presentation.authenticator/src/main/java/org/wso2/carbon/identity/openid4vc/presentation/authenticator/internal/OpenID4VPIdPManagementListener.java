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
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.core.util.KeyStoreUtil;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.server.util.VPAuthenticatorUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.listener.AbstractIdentityProviderMgtListener;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;

/**
 * Provisions an ECDSA P-256 keypair into the tenant keystore whenever a new IdP backed by
 * {@code OpenID4VPAuthenticator} is created.
 *
 * <p>This covers tenants that existed before the carbon-multitenancy ECDSA provisioning commit
 * was deployed: those tenants' keystores have no {@code <tenantDomain>_ec} entry, so the first
 * OID4VP IdP creation triggers lazy provisioning here.</p>
 *
 * <p>The operation is idempotent — if the alias already exists the method returns immediately.
 * The certificate is generated identically to {@code TenantKeyPairUtil.addKeyEntry} in
 * carbon-multitenancy.</p>
 */
public class OpenID4VPIdPManagementListener extends AbstractIdentityProviderMgtListener {

    private static final Log LOG = LogFactory.getLog(OpenID4VPIdPManagementListener.class);

    private static final String OID4VP_AUTHENTICATOR_NAME = "OpenID4VPAuthenticator";
    private static final String EC_ALGORITHM = "EC";
    private static final String EC_CURVE = "secp256r1";
    private static final String SIGN_ALGORITHM = "SHA256withECDSA";

    @Override
    public int getDefaultOrderId() {

        return 110;
    }

    @Override
    public boolean doPostAddIdP(IdentityProvider identityProvider, String tenantDomain)
            throws IdentityProviderManagementException {

        if (!isOid4vpIdP(identityProvider)) {
            return true;
        }

        try {
            String alias = KeyStoreUtil.getTenantECKeyAlias(tenantDomain);
            LOG.info("OpenID4VP IdP created for tenant [" + tenantDomain
                    + "]. Checking ECDSA keypair under alias '" + alias + "'.");
            provisionEcdsaKeyPairIfAbsent(tenantDomain, alias);
        } catch (Exception e) {
            // Non-fatal: IdP creation succeeds; log the failure so it can be diagnosed.
            LOG.error("Failed to provision ECDSA keypair for tenant [" + tenantDomain
                    + "]. The IdP was created but VP request signing may be unavailable.", e);
        }

        return true;
    }

    private boolean isOid4vpIdP(IdentityProvider identityProvider) {

        if (identityProvider == null) {
            return false;
        }
        FederatedAuthenticatorConfig[] configs = identityProvider.getFederatedAuthenticatorConfigs();
        if (configs == null) {
            return false;
        }
        return Arrays.stream(configs)
                .anyMatch(c -> OID4VP_AUTHENTICATOR_NAME.equals(c.getName()));
    }

    private void provisionEcdsaKeyPairIfAbsent(String tenantDomain, String alias) throws Exception {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        KeyStoreManager ksm = KeyStoreManager.getInstance(tenantId);
        KeyStore ks = VPAuthenticatorUtil.getTenantKeyStore(ksm, tenantDomain);

        if (ks.containsAlias(alias)) {
            LOG.info("ECDSA alias '" + alias + "' already exists for tenant [" + tenantDomain + "]. Skipping.");
            return;
        }

        LOG.info("Generating P-256 ECDSA keypair for tenant [" + tenantDomain + "] alias '" + alias + "'.");

        // Register BouncyCastle provider (matches TenantKeyPairUtil behaviour).
        CryptoUtil.getDefaultCryptoUtil();

        KeyPair keyPair = generateEcKeyPair();
        X509Certificate cert = buildSelfSignedCert(keyPair, tenantDomain);

        String ksName = resolveKeyStoreName(tenantDomain);
        char[] keyPassword = ksm.getPrivateKeyPassword(ksName);
        try {
            ks.setKeyEntry(alias, keyPair.getPrivate(), keyPassword, new Certificate[]{cert});
            ksm.updateKeyStore(ksName, ks);
        } finally {
            if (keyPassword != null) {
                Arrays.fill(keyPassword, '\0');
            }
        }

        LOG.info("ECDSA P-256 keypair provisioned for tenant [" + tenantDomain + "] alias '" + alias + "'.");
    }

    private KeyPair generateEcKeyPair() throws Exception {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(EC_ALGORITHM);
        kpg.initialize(new ECGenParameterSpec(EC_CURVE));
        return kpg.generateKeyPair();
    }

    /**
     * Builds a self-signed X.509 certificate identical to what {@code TenantKeyPairUtil.addKeyEntry}
     * produces for the EC entry: same DN format, same 30-day back-dated notBefore, same 10-year validity,
     * same DNS SAN extension, and explicit BouncyCastle provider for the signer and converter.
     */
    private X509Certificate buildSelfSignedCert(KeyPair keyPair, String tenantDomain) throws Exception {

        String commonName = "CN=" + tenantDomain + ", OU=None, O=None, L=None, C=None";
        X500Name dn = new X500Name(commonName);

        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30);
        Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365 * 10);
        BigInteger serial = new BigInteger(32, new SecureRandom());

        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                dn, serial, notBefore, notAfter, dn, publicKeyInfo);
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, tenantDomain)));

        String bcProvider = CryptoUtil.getJCEProvider();
        ContentSigner signer = new JcaContentSignerBuilder(SIGN_ALGORITHM)
                .setProvider(bcProvider)
                .build(keyPair.getPrivate());

        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(bcProvider)
                .getCertificate(holder);
    }

    private String resolveKeyStoreName(String tenantDomain) {

        if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            return KeyStoreUtil.getKeyStoreFileName(null);
        }
        return tenantDomain.trim().replace(".", "-") + ".jks";
    }
}
