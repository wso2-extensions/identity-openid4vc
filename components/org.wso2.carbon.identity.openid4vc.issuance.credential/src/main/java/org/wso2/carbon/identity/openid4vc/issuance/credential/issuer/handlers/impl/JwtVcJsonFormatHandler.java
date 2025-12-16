/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.handlers.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openid4vc.issuance.common.util.CommonUtil;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.CredentialIssuerContext;
import org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.builders.W3CVCDataModelBuilder;
import org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.handlers.CredentialFormatHandler;
import org.wso2.carbon.identity.openid4vc.issuance.credential.util.CredentialIssuanceUtil;

import java.security.Key;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.CONTEXT_OPENID4VCI;
import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.JWT_VC_JSON_FORMAT;
import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.VC_CLAIM;

/**
 * Handler for JWT VC JSON format credentials.
 */
public class JwtVcJsonFormatHandler implements CredentialFormatHandler {

    private static final Log LOG = LogFactory.getLog(JwtVcJsonFormatHandler.class);
    private static final String FORMAT = JWT_VC_JSON_FORMAT;

    @Override
    public String getFormat() {
        return FORMAT;
    }

    @Override
    public String issueCredential(CredentialIssuerContext credentialIssuerContext) throws CredentialIssuanceException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Issuing JWT VC JSON credential for configuration: " +
                    credentialIssuerContext.getConfigurationId());
        }

        JWTClaimsSet jwtClaimsSet = createJWTClaimSet(credentialIssuerContext);
        return signJWT(jwtClaimsSet, credentialIssuerContext);
    }

    private JWTClaimsSet createJWTClaimSet(CredentialIssuerContext credentialIssuerContext)
            throws CredentialIssuanceException {

        String issuerUrl;
        try {
            issuerUrl = buildCredentialIssuerUrl(credentialIssuerContext.getTenantDomain());
        } catch (URLBuilderException e) {
            throw new CredentialIssuanceException("Error building credential issuer URL", e);
        }

        Instant now = Instant.now();

        int expiryIn = credentialIssuerContext.getVCTemplate().getExpiresIn();
        Instant validUntil = now.plusSeconds(expiryIn);

        String id = UUID.randomUUID().toString();

        Map<String, Object> vcStructure = buildVerifiableCredential(credentialIssuerContext, id, issuerUrl, now,
                validUntil);

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();

        // Standard JWT claims
        jwtClaimsSetBuilder.issuer(issuerUrl);
        jwtClaimsSetBuilder.jwtID(id);
        jwtClaimsSetBuilder.issueTime(java.util.Date.from(now));
        jwtClaimsSetBuilder.notBeforeTime(java.util.Date.from(now));
        jwtClaimsSetBuilder.expirationTime(java.util.Date.from(validUntil));

        // VC claim
        jwtClaimsSetBuilder.claim(VC_CLAIM, vcStructure);

        return jwtClaimsSetBuilder.build();
    }

    /**
     * Builds the W3C Verifiable Credential structure according to W3C VC Data Model v2.
     *
     * @param credentialIssuerContext the credential issuer context
     * @param issuerUrl the issuer URL
     * @param validFrom the valid from instant
     * @param validUntil the valid until instant
     * @return the W3C VC claim map
     */
    private Map<String, Object> buildVerifiableCredential(CredentialIssuerContext credentialIssuerContext, String id,
                                                          String issuerUrl, Instant validFrom, Instant validUntil) {

        String credentialType = credentialIssuerContext.getVCTemplate().getIdentifier();
        Map<String, String> claims = credentialIssuerContext.getClaims();

        return new W3CVCDataModelBuilder()
                .id(id)
                .addContext(credentialType)
                .addType(credentialType)
                .issuer(issuerUrl)
                .validFrom(validFrom)
                .validUntil(validUntil)
                .credentialSubject(claims)
                .build();
    }

    /**
     * Builds the credential issuer URL.
     *
     * @param tenantDomain the tenant domain
     * @return the credential issuer URL
     * @throws URLBuilderException if an error occurs while building the URL
     */
    private String buildCredentialIssuerUrl(String tenantDomain) throws URLBuilderException {

        return CommonUtil.buildServiceUrl(tenantDomain, CONTEXT_OPENID4VCI).getAbsolutePublicURL();
    }

    /**
     * Signs the JWT.
     *
     * @param jwtClaimsSet the JWT claims set
     * @param credentialIssuerContext the credential issuer context
     * @return the signed JWT as a string
     * @throws CredentialIssuanceException if an error occurs while signing the JWT
     */
    private String signJWT(JWTClaimsSet jwtClaimsSet, CredentialIssuerContext credentialIssuerContext)
            throws CredentialIssuanceException {

        String signatureAlgorithm = credentialIssuerContext.getVCTemplate()
                .getSigningAlgorithm();
        if (JWSAlgorithm.RS256.getName().equals(signatureAlgorithm)) {
            return signJWTWithRSA(jwtClaimsSet, credentialIssuerContext);
        } else {
            throw new CredentialIssuanceException("Invalid signature algorithm provided. " + signatureAlgorithm);
        }
    }

    /**
     * Signs the JWT using RSA algorithm.
     *
     * @param jwtClaimsSet the JWT claims set
     * @param credentialIssuerContext the credential issuer context
     * @return the signed JWT as a string
     * @throws CredentialIssuanceException if an error occurs while signing the JWT
     */
    private String signJWTWithRSA(JWTClaimsSet jwtClaimsSet, CredentialIssuerContext credentialIssuerContext)
            throws CredentialIssuanceException {

        try {
            String tenantDomain = credentialIssuerContext.getTenantDomain();
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

            Key privateKey = CredentialIssuanceUtil.getPrivateKey(tenantDomain);
            JWSSigner signer = OAuth2Util.createJWSSigner((RSAPrivateKey) privateKey);
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256);
            Certificate certificate;
            try {
                certificate = OAuth2Util.getCertificate(tenantDomain, tenantId);
            } catch (IdentityOAuth2Exception e) {
                throw new CredentialIssuanceException("Error obtaining the certificate for tenant: " + tenantDomain, e);
            }
            String certThumbPrint;
            try {
                certThumbPrint = OAuth2Util.getThumbPrintWithPrevAlgorithm(certificate, false);
            } catch (IdentityOAuth2Exception e) {
                throw new CredentialIssuanceException("Error obtaining the certificate thumbprint for tenant: "
                        + tenantDomain, e);
            }
            try {
                headerBuilder.keyID(OAuth2Util.getKID(OAuth2Util.getCertificate(tenantDomain, tenantId),
                        (JWSAlgorithm) JWSAlgorithm.RS256, tenantDomain));
            } catch (IdentityOAuth2Exception e) {
                throw new CredentialIssuanceException("Error obtaining the KID for tenant: " + tenantDomain, e);
            }
            headerBuilder.x509CertThumbprint(new Base64URL(certThumbPrint));
            SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), jwtClaimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new CredentialIssuanceException("Error occurred while signing JWT", e);
        }
    }
}

