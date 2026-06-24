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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vc.presentation.server.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.core.util.KeyStoreUtil;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.config.OpenID4VPConfigService;
import org.wso2.carbon.identity.openid4vc.presentation.common.config.OpenID4VPTenantConfig;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.server.internal.VPServerDataHolder;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

/**
 * Utility class for VP server related operations.
 */
public final class VPAuthenticatorUtil {

    private static final Log LOG = LogFactory.getLog(VPAuthenticatorUtil.class);

    private VPAuthenticatorUtil() { }

    /**
     * Resolve tenant-aware base URL from framework utilities.
     */
    public static String resolveTenantAwareBaseUrl() throws VPAuthenticatorException {

        try {
            String baseUrl = ServiceURLBuilder.create()
                    .build(IdentityUtil.getHostName())
                    .getAbsolutePublicUrlWithoutPath();

            org.wso2.carbon.context.PrivilegedCarbonContext ctx =
                    org.wso2.carbon.context.PrivilegedCarbonContext.getThreadLocalCarbonContext();
            String tenantDomain = ctx.getTenantDomain();

            if (tenantDomain != null && !Constraints.SUPER_TENANT_DOMAIN.equals(tenantDomain)) {
                return baseUrl + Constraints.TENANT_PATH_PREFIX + tenantDomain;
            }
            return baseUrl;
        } catch (URLBuilderException e) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Error while resolving tenant-aware base URL.", e);
        }
    }

    /**
     * Resolve base URL from framework utilities.
     */
    public static String resolveBaseUrl() throws VPAuthenticatorException {

        try {
            return ServiceURLBuilder.create()
                    .build(IdentityUtil.getHostName())
                    .getAbsolutePublicUrlWithoutPath();
        } catch (URLBuilderException e) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Error while resolving base URL.", e);
        }
    }

    /**
     * Returns the fixed SIOPv2 request audience value.
     */
    public static String resolveRequestAudience() {

        return OpenID4VPConstants.Protocol.REQUEST_AUDIENCE;
    }

    /**
     * Resolve client_id_scheme for a tenant.
     */
    public static String resolveClientIdScheme(String tenantDomain) {

        String tenantValue = getTenantConfigValue(tenantDomain, OpenID4VPTenantConfig::getClientIdScheme);
        return StringUtils.isNotBlank(tenantValue) ? tenantValue : Constraints.CLIENT_ID_SCHEME_X509_SAN_DNS;
    }

    /**
     * Resolve response_mode for a tenant.
     */
    public static String resolveResponseMode(String tenantDomain) {

        String tenantValue = getTenantConfigValue(tenantDomain, OpenID4VPTenantConfig::getResponseMode);
        return StringUtils.isNotBlank(tenantValue) ? tenantValue
                : OpenID4VPConstants.Protocol.RESPONSE_MODE_DIRECT_POST;
    }

    /**
     * Resolve the registration certificate (verifier_attestation) for a tenant.
     */
    public static String resolveRegistrationCertificate(String tenantDomain) {

        return getTenantConfigValue(tenantDomain, OpenID4VPTenantConfig::getRegistrationCertificate);
    }

    private static String getTenantConfigValue(String tenantDomain,
            java.util.function.Function<OpenID4VPTenantConfig, String> extractor) {

        try {
            OpenID4VPConfigService configService = VPServerDataHolder.getOpenID4VPConfigService();
            if (configService == null || StringUtils.isBlank(tenantDomain)) {
                return null;
            }
            OpenID4VPTenantConfig cfg = configService.getConfig(tenantDomain);
            return extractor.apply(cfg);
        } catch (Exception e) {
            LOG.warn("Failed to read tenant config for " + tenantDomain + "; using server default.", e);
            return null;
        }
    }

    /**
     * Resolve signing key alias for a specific tenant.
     */
    public static String resolveSigningKeyAlias(String tenantDomain) {

        try {
            return KeyStoreUtil.getTenantECKeyAlias(tenantDomain);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to resolve ECDSA key alias for tenant: " + tenantDomain, e);
        }
    }

    /**
     * Resolve the effective client_id for a tenant.
     */
    public static String resolveClientId(String scheme, String baseUrl, String tenantDomain)
            throws VPAuthenticatorException {

        String override = getTenantConfigValue(tenantDomain, OpenID4VPTenantConfig::getClientId);
        if (StringUtils.isNotBlank(override)) {
            return override;
        }
        return resolveClientIdForScheme(scheme, baseUrl, tenantDomain);
    }

    /**
     * Resolve the client_id value based on the configured scheme.
     */
    public static String resolveClientIdForScheme(String scheme, String baseUrl, String tenantDomain)
            throws VPAuthenticatorException {

        if (Constraints.CLIENT_ID_SCHEME_X509_SAN_DNS.equals(scheme)) {
            return Constraints.CLIENT_ID_SCHEME_X509_SAN_DNS + ":" + resolveServerSanDns(tenantDomain);
        } else if (Constraints.CLIENT_ID_SCHEME_X509_HASH.equals(scheme)) {
            return Constraints.CLIENT_ID_SCHEME_X509_HASH + ":" + resolveServerCertHash(tenantDomain);
        } else {
            return baseUrl + Constraints.RESPONSE_URI_ENDPOINT;
        }
    }

    /**
     * Compute the base64url SHA-256 hash of the tenant's signing certificate.
     */
    public static String resolveServerCertHash(String tenantDomain) throws VPAuthenticatorException {

        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            KeyStoreManager ksm = KeyStoreManager.getInstance(tenantId);
            KeyStore ks = getTenantKeyStore(ksm, tenantDomain);
            String alias = resolveSigningKeyAlias(tenantDomain);
            java.security.cert.Certificate[] chain = ks.getCertificateChain(alias);
            X509Certificate cert = (X509Certificate) (chain != null && chain.length > 0
                    ? chain[0] : ks.getCertificate(alias));
            return computeCertHash(cert);
        } catch (VPAuthenticatorException e) {
            throw e;
        } catch (Exception e) {
            throw new VPAuthenticatorServerException(
                    VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to compute cert hash for x509_hash scheme.", e);
        }
    }

    /**
     * Compute base64url(SHA-256(DER(cert))).
     */
    public static String computeCertHash(X509Certificate cert) throws VPAuthenticatorException {

        try {
            byte[] derEncoded = cert.getEncoded();
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(derEncoded);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new VPAuthenticatorServerException(
                    VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to compute SHA-256 hash of certificate.", e);
        }
    }

    /**
     * Load the tenant signing certificate and extract the first dNSName SAN entry.
     */
    public static String resolveServerSanDns(String tenantDomain) throws VPAuthenticatorException {

        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            KeyStoreManager ksm = KeyStoreManager.getInstance(tenantId);
            KeyStore ks = getTenantKeyStore(ksm, tenantDomain);
            String alias = resolveSigningKeyAlias(tenantDomain);
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            String sanDns = extractSanDns(cert);
            if (StringUtils.isBlank(sanDns)) {
                throw new VPAuthenticatorServerException(
                        VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                        "No dNSName SAN entry found in server certificate. "
                                + "x509_san_dns scheme requires the TLS certificate to have a SAN dNSName.");
            }
            return sanDns;
        } catch (VPAuthenticatorException e) {
            throw e;
        } catch (Exception e) {
            throw new VPAuthenticatorServerException(
                    VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to load server certificate for x509_san_dns scheme.", e);
        }
    }

    /**
     * Extract the first dNSName Subject Alternative Name entry from an X.509 certificate.
     */
    public static String extractSanDns(X509Certificate cert) {

        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    if (san.size() >= 2 && Integer.valueOf(2).equals(san.get(0))) {
                        return (String) san.get(1);
                    }
                }
            }
        } catch (CertificateParsingException e) {
            LOG.warn("Failed to parse SAN extensions from certificate.", e);
        }
        return null;
    }

    /**
     * Load the correct keystore for the given tenant.
     */
    public static KeyStore getTenantKeyStore(KeyStoreManager ksm, String tenantDomain) throws Exception {

        if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            return ksm.getPrimaryKeyStore();
        }
        String ksName = tenantDomain.trim().replace(".", "-") + ".jks";
        return ksm.getKeyStore(ksName);
    }
}
