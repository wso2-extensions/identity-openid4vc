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
import com.nimbusds.jose.JOSEObjectType;
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
import org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.handlers.CredentialFormatHandler;
import org.wso2.carbon.identity.openid4vc.issuance.credential.util.CredentialIssuanceUtil;
import org.wso2.carbon.identity.openid4vc.sdjwt.Disclosure;
import org.wso2.carbon.identity.openid4vc.sdjwt.SDJWT;
import org.wso2.carbon.identity.openid4vc.sdjwt.SDObjectBuilder;
import org.wso2.carbon.identity.openid4vc.sdjwt.constant.SDJWTConstants;
import org.wso2.carbon.identity.openid4vc.sdjwt.exception.SDJWTException;

import java.security.Key;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.CONTEXT_OPENID4VCI;

/**
 * Handler for SD-JWT VC format credentials.
 * <p>
 * This handler issues credentials in the SD-JWT format as specified in
 * draft-ietf-oauth-selective-disclosure-jwt. All claims from the credential
 * subject are made selectively disclosable.
 *
 * @see <a href=
 *      "https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/">SD-JWT
 *      Specification</a>
 */
public class SdJwtVcFormatHandler implements CredentialFormatHandler {

    private static final Log LOG = LogFactory.getLog(SdJwtVcFormatHandler.class);
    private static final String FORMAT = SDJWTConstants.FORMAT_VC_SD_JWT;

    @Override
    public String getFormat() {

        return FORMAT;
    }

    @Override
    public String issueCredential(CredentialIssuerContext credentialIssuerContext) throws CredentialIssuanceException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Issuing SD-JWT VC credential for configuration: " +
                    credentialIssuerContext.getConfigurationId());
        }

        try {
            // Build SD-JWT payload with selectively disclosable claims
            SDObjectBuilder builder = buildSDJwtPayload(credentialIssuerContext);
            Map<String, Object> payload = builder.build();
            List<Disclosure> disclosures = builder.getDisclosures();

            // Sign the credential JWT
            String signedJwt = signCredentialJwt(payload, credentialIssuerContext);

            // Create and serialize the SD-JWT
            SDJWT sdJwt = new SDJWT(signedJwt, disclosures);
            String serialized = sdJwt.serialize();

            if (LOG.isDebugEnabled()) {
                LOG.debug("Successfully issued SD-JWT VC with " + disclosures.size() + " disclosures");
            }

            return serialized;
        } catch (SDJWTException e) {
            throw new CredentialIssuanceException("Error creating SD-JWT disclosure", e);
        }
    }

    /**
     * Build the SD-JWT payload with standard claims and selectively disclosable
     * user claims.
     *
     * @param context the credential issuer context
     * @return SDObjectBuilder with all claims added
     * @throws SDJWTException              if there's an error creating disclosures
     * @throws CredentialIssuanceException if there's an error building the issuer
     *                                     URL
     */
    private SDObjectBuilder buildSDJwtPayload(CredentialIssuerContext context)
            throws SDJWTException, CredentialIssuanceException {

        SDObjectBuilder builder = new SDObjectBuilder();

        // Add non-disclosable standard claims
        String issuerUrl;
        try {
            issuerUrl = buildCredentialIssuerUrl(context.getTenantDomain());
        } catch (URLBuilderException e) {
            throw new CredentialIssuanceException("Error building credential issuer URL", e);
        }

        Instant now = Instant.now();
        int expiryIn = context.getVCTemplate().getExpiresIn();
        Instant expiry = now.plusSeconds(expiryIn);

        builder.putClaim("iss", issuerUrl);
        builder.putClaim("iat", now.getEpochSecond());
        builder.putClaim("exp", expiry.getEpochSecond());

        // vct (Verifiable Credential Type) - required for SD-JWT VC
        String credentialType = context.getVCTemplate().getIdentifier();
        builder.putClaim(SDJWTConstants.CLAIM_VCT, credentialType);

        // Add all user claims as selectively disclosable
        Map<String, String> claims = context.getClaims();
        if (claims != null) {
            for (Map.Entry<String, String> entry : claims.entrySet()) {
                builder.putSDClaim(entry.getKey(), entry.getValue());
            }
        }

        return builder;
    }

    /**
     * Build the credential issuer URL.
     *
     * @param tenantDomain the tenant domain
     * @return the credential issuer URL
     * @throws URLBuilderException if an error occurs while building the URL
     */
    private String buildCredentialIssuerUrl(String tenantDomain) throws URLBuilderException {

        return CommonUtil.buildServiceUrl(tenantDomain, CONTEXT_OPENID4VCI).getAbsolutePublicURL();
    }

    /**
     * Sign the credential JWT with the SD-JWT typ header.
     *
     * @param payload the JWT payload as a Map
     * @param context the credential issuer context
     * @return the signed JWT as a string
     * @throws CredentialIssuanceException if an error occurs while signing
     */
    private String signCredentialJwt(Map<String, Object> payload, CredentialIssuerContext context)
            throws CredentialIssuanceException {

        String signatureAlgorithm = context.getVCTemplate().getSigningAlgorithm();
        if (JWSAlgorithm.RS256.getName().equals(signatureAlgorithm)) {
            return signWithRSA(payload, context);
        } else {
            throw new CredentialIssuanceException("Invalid signature algorithm provided: " + signatureAlgorithm);
        }
    }

    /**
     * Sign the JWT using RSA algorithm.
     *
     * @param payload the JWT payload as a Map
     * @param context the credential issuer context
     * @return the signed JWT as a string
     * @throws CredentialIssuanceException if an error occurs while signing
     */
    private String signWithRSA(Map<String, Object> payload, CredentialIssuerContext context)
            throws CredentialIssuanceException {

        try {
            String tenantDomain = context.getTenantDomain();
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

            // Get private key and create signer
            Key privateKey = CredentialIssuanceUtil.getPrivateKey(tenantDomain);
            JWSSigner signer = OAuth2Util.createJWSSigner((RSAPrivateKey) privateKey);

            // Build header with typ = "dc+sd-jwt"
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256);
            headerBuilder.type(new JOSEObjectType(SDJWTConstants.TYP_VC_SD_JWT));

            // Add certificate thumbprint and key ID
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
            headerBuilder.x509CertThumbprint(new Base64URL(certThumbPrint));

            String keyId = OAuth2Util.getKID(certificate, JWSAlgorithm.RS256, tenantDomain);
            headerBuilder.keyID(keyId);

            // Create and sign JWT using builder
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
            for (Map.Entry<String, Object> entry : payload.entrySet()) {
                claimsBuilder.claim(entry.getKey(), entry.getValue());
            }
            JWTClaimsSet claimsSet = claimsBuilder.build();

            SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), claimsSet);
            signedJWT.sign(signer);

            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new CredentialIssuanceException("Error signing SD-JWT", e);
        } catch (IdentityOAuth2Exception e) {
            throw new CredentialIssuanceException("Error obtaining certificate or key for tenant: " +
                    context.getTenantDomain(), e);
        }
    }
}
