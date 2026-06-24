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

package org.wso2.carbon.identity.openid4vc.presentation.server.service.impl;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.server.internal.VPServerDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.VPContext;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.server.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints;
import org.wso2.carbon.identity.openid4vc.presentation.server.util.VPAuthenticatorUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Implementation of VPRequestService for managing VP authorization requests.
 */
public class VPRequestServiceImpl extends VPRequestService {

    private static final org.apache.commons.logging.Log LOG =
            org.apache.commons.logging.LogFactory.getLog(VPRequestServiceImpl.class);

    private static final String PROP_PRESENTATION_DEFINITION_ID = Constraints.PROP_PRESENTATION_DEFINITION_ID;
    private static final long DEFAULT_EXPIRY_MS = 60000;

    private final AtomicReference<PresentationDefinitionService> presentationDefinitionServiceRef;
    private volatile String baseUrl;

    public VPRequestServiceImpl() {
        this.presentationDefinitionServiceRef =
                new AtomicReference<>(VPServerDataHolder.getPresentationDefinitionService());
    }

    public VPRequestServiceImpl(PresentationDefinitionService presentationDefinitionService,
                                String baseUrl) {
        this.presentationDefinitionServiceRef = new AtomicReference<>(presentationDefinitionService);
        this.baseUrl = baseUrl;
    }

    private PresentationDefinitionService getPresentationDefinitionService() throws VPAuthenticatorException {
        PresentationDefinitionService service = presentationDefinitionServiceRef.get();
        if (service == null) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Presentation definition service is not initialized.");
        }
        return service;
    }

    @Override
    public String generateRequestJwt(String requestId) throws VPAuthenticatorException {

        AuthenticationContext context = FrameworkUtils.getAuthenticationContextFromCache(requestId);
        if (context == null) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "No authentication context found for request ID: " + requestId);
        }

        Object vpContextObj = context.getProperty(Constraints.CONTEXT_VP_CONTEXT);
        if (!(vpContextObj instanceof VPContext)) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "No VP context found for request ID: " + requestId);
        }

        String baseUrl = VPAuthenticatorUtil.resolveBaseUrl();
        String tenantDomain = context.getProperty(Constraints.CONTEXT_EFFECTIVE_TENANT_DOMAIN) instanceof String
                ? (String) context.getProperty(Constraints.CONTEXT_EFFECTIVE_TENANT_DOMAIN)
                : context.getTenantDomain();
        String scheme = VPAuthenticatorUtil.resolveClientIdScheme(tenantDomain);
        String responseMode = VPAuthenticatorUtil.resolveResponseMode(tenantDomain);

        String clientId = VPAuthenticatorUtil.resolveClientIdForScheme(scheme, baseUrl, tenantDomain);
        String presentationDefinitionId = MapUtils.getString(context.getAuthenticatorProperties(),
                PROP_PRESENTATION_DEFINITION_ID);

        if (StringUtils.isBlank(presentationDefinitionId)) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_PRESENTATION_DEFINITION,
                    "No presentation definition found for the application.");
        }

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        long expiresAt = System.currentTimeMillis() + DEFAULT_EXPIRY_MS;

        // Store nonce in VPContext so the submission servlet can validate KB-JWT nonce binding (spec §8.6).
        // Also generate ephemeral key for direct_post.jwt. Both updates share one cache write.
        VPContext vpContext = (VPContext) vpContextObj;
        // Reuse the nonce if already generated (wallets like Heidi/ARF fetch request_uri twice —
        // once to show consent and again on confirm; generating a new nonce on the second fetch
        // causes a mismatch with the KB-JWT that was built using the first nonce).
        String existingNonce = vpContext.getNonce();
        String nonce = StringUtils.isNotBlank(existingNonce) ? existingNonce : UUID.randomUUID().toString();
        vpContext.setNonce(nonce);

        ECKey ephemeralPublicKey = null;
        if (Constraints.RESPONSE_MODE_DIRECT_POST_JWT.equals(responseMode)) {
            try {
                String existingEphemeralJwk = vpContext.getEphemeralPrivateKeyJwk();
                ECKey ephemeralKeyPair;
                if (StringUtils.isNotBlank(existingEphemeralJwk)) {
                    // Reuse existing ephemeral key pair — same reason as nonce reuse above.
                    try {
                        ephemeralKeyPair = ECKey.parse(existingEphemeralJwk);
                    } catch (java.text.ParseException pe) {
                        throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                                "Failed to parse stored ephemeral EC key for direct_post.jwt.", pe);
                    }
                } else {
                    ephemeralKeyPair = new ECKeyGenerator(Curve.P_256)
                            .keyID(requestId)
                            .generate();
                    vpContext.setEphemeralPrivateKeyJwk(ephemeralKeyPair.toJSONString());
                }
                ephemeralPublicKey = ephemeralKeyPair.toPublicJWK();
            } catch (com.nimbusds.jose.JOSEException e) {
                throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                        "Failed to generate ephemeral EC key pair for direct_post.jwt.", e);
            }
        }

        context.setProperty(Constraints.CONTEXT_VP_CONTEXT, vpContext);
        FrameworkUtils.addAuthenticationContextToCache(requestId, context);

        VPRequest vpRequest = new VPRequest.Builder()
                .requestId(requestId)
                .clientId(clientId)
                .nonce(nonce)
                .presentationDefinitionId(presentationDefinitionId)
                .responseUri(baseUrl + Constraints.RESPONSE_URI_ENDPOINT)
                .responseMode(responseMode)
                .status(VPRequestStatus.ACTIVE)
                .expiresAt(expiresAt)
                .tenantId(tenantId)
                .build();

        String registrationCert = VPAuthenticatorUtil.resolveRegistrationCertificate(tenantDomain);
        return buildRequestObjectJwt(vpRequest, tenantDomain, ephemeralPublicKey, scheme, registrationCert);
    }

    @Override
    public String buildRequestJwt(VPRequest vpRequest, String tenantDomain,
            ECKey ephemeralPublicKey, String clientIdScheme, String registrationCert)
            throws VPAuthenticatorException {

        return buildRequestObjectJwt(vpRequest, tenantDomain, ephemeralPublicKey,
                clientIdScheme, registrationCert);
    }

    private String buildRequestObjectJwt(final VPRequest vpRequest,
                                         final String tenantDomain,
                                         final ECKey ephemeralPublicKey,
                                         final String clientIdScheme,
                                         final String registrationCert)
            throws VPAuthenticatorException {

        try {
            String responseUri = vpRequest.getResponseUri();
            String scheme = StringUtils.defaultIfBlank(clientIdScheme, Constraints.CLIENT_ID_SCHEME_X509_SAN_DNS);

            // redirect_uri: MUST NOT sign per spec §5.7 (no mechanism for wallet to obtain trusted key).
            // x509 schemes: sign and embed x5c chain.
            final String clientId;
            JWSHeader jwsHeader = null;   // null → produce unsigned PlainJWT
            JWSSigner jwsSigner = null;

            if (Constraints.CLIENT_ID_SCHEME_REDIRECT_URI.equals(scheme)) {
                // redirect_uri: client_id = response_uri; request must be unsigned.
                clientId = responseUri;

            } else {
                // All signed schemes: load keystore and set up signer.
                int tenantId = vpRequest.getTenantId();
                KeyStoreManager ksm = KeyStoreManager.getInstance(tenantId);
                KeyStore ks = VPAuthenticatorUtil.getTenantKeyStore(ksm, tenantDomain);
                String keyAlias = VPAuthenticatorUtil.resolveSigningKeyAlias(tenantDomain);
                char[] keyPassword = resolveKeyPassword(ksm, tenantDomain);
                PrivateKey privateKey = (PrivateKey) ks.getKey(keyAlias, keyPassword);

                final JWSAlgorithm jwsAlg;
                if (privateKey instanceof RSAPrivateKey) {
                    jwsAlg = JWSAlgorithm.RS256;
                    jwsSigner = new RSASSASigner(privateKey);
                } else if (privateKey instanceof ECPrivateKey) {
                    jwsAlg = JWSAlgorithm.ES256;
                    jwsSigner = new ECDSASigner((ECPrivateKey) privateKey);
                } else if (privateKey != null && ("Ed25519".equalsIgnoreCase(privateKey.getAlgorithm())
                        || "EdDSA".equalsIgnoreCase(privateKey.getAlgorithm()))) {
                    jwsAlg = JWSAlgorithm.EdDSA;
                    OctetKeyPair okp = (OctetKeyPair) JWK.load(ks, keyAlias, keyPassword);
                    jwsSigner = new Ed25519Signer(okp);
                } else {
                    throw new VPAuthenticatorServerException(
                            VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                            "Unsupported key algorithm for scheme " + scheme + ": "
                                    + (privateKey != null ? privateKey.getAlgorithm() : "null"));
                }

                {
                    // x509_san_dns / x509_hash: embed cert chain.
                    java.security.cert.Certificate[] certChain = ks.getCertificateChain(keyAlias);
                    X509Certificate cert = (X509Certificate) (certChain != null && certChain.length > 0
                            ? certChain[0] : ks.getCertificate(keyAlias));

                    if (Constraints.CLIENT_ID_SCHEME_X509_SAN_DNS.equals(scheme)) {
                        String sanDns = VPAuthenticatorUtil.extractSanDns(cert);
                        if (StringUtils.isBlank(sanDns)) {
                            throw new VPAuthenticatorServerException(
                                    VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                                    "No dNSName SAN entry in server certificate. "
                                            + "x509_san_dns requires a SAN dNSName in the TLS certificate.");
                        }
                        clientId = Constraints.CLIENT_ID_SCHEME_X509_SAN_DNS + ":" + sanDns;
                    } else {
                        clientId = Constraints.CLIENT_ID_SCHEME_X509_HASH + ":"
                                + VPAuthenticatorUtil.computeCertHash(cert);
                    }

                    List<com.nimbusds.jose.util.Base64> x5cChain = new java.util.ArrayList<>();
                    if (certChain != null && certChain.length > 1) {
                        for (java.security.cert.Certificate c : certChain) {
                            x5cChain.add(com.nimbusds.jose.util.Base64.encode(c.getEncoded()));
                        }
                    } else {
                        x5cChain.add(com.nimbusds.jose.util.Base64.encode(cert.getEncoded()));
                    }
                    String certThumbprint = VPAuthenticatorUtil.computeCertHash(cert);

                    jwsHeader = new JWSHeader.Builder(jwsAlg)
                            .type(new JOSEObjectType(Constraints.JOSE_TYPE_OAUTH_AUTHZ_REQ))
                            .keyID(certThumbprint)
                            .x509CertChain(x5cChain)
                            .build();
                }
            }

            // --- Build claims (common to all schemes) ---
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
            // iss is omitted for redirect_uri: unsigned request has no trusted key to bind to.
            if (!Constraints.CLIENT_ID_SCHEME_REDIRECT_URI.equals(scheme)) {
                claimsBuilder.issuer(clientId);
            }
            claimsBuilder
                    .audience(VPAuthenticatorUtil.resolveRequestAudience())
                    .claim(OpenID4VPConstants.RequestParams.CLIENT_ID, clientId)
                    .claim("client_id_scheme", scheme)
                    .claim(OpenID4VPConstants.RequestParams.RESPONSE_TYPE,
                            OpenID4VPConstants.Protocol.RESPONSE_TYPE_VP_TOKEN)
                    .claim(OpenID4VPConstants.RequestParams.RESPONSE_MODE,
                            vpRequest.getResponseMode())
                    .claim(OpenID4VPConstants.RequestParams.RESPONSE_URI, responseUri)
                    .claim(OpenID4VPConstants.RequestParams.NONCE, vpRequest.getNonce())
                    .claim(OpenID4VPConstants.RequestParams.STATE, vpRequest.getRequestId())
                    .issueTime(new Date())
                    .expirationTime(new Date(System.currentTimeMillis() + DEFAULT_EXPIRY_MS))
                    .jwtID(UUID.randomUUID().toString());

            // dcql_query only — spec §5.4 forbids sending both presentation_definition and dcql_query.
            PresentationDefinition pd = getPresentationDefinitionService()
                    .getPresentationDefinitionById(vpRequest.getPresentationDefinitionId(),
                            vpRequest.getTenantId());
            claimsBuilder.claim("dcql_query", buildDcqlQuery(pd));

            // Add client_metadata.
            Map<String, Object> clientMetadata = new HashMap<>();
            clientMetadata.put(Constraints.METADATA_CLIENT_NAME, clientId);
            Map<String, Object> vpFormats = new HashMap<>();
            Map<String, Object> vcSdJwt = new HashMap<>();
            vcSdJwt.put("sd-jwt_alg_values", java.util.Arrays.asList("ES256", "EdDSA"));
            vcSdJwt.put("kb-jwt_alg_values", java.util.Arrays.asList("ES256", "EdDSA"));
            vpFormats.put(Constraints.FORMAT_VC_SD_JWT, vcSdJwt);
            vpFormats.put("dc+sd-jwt", vcSdJwt);
            clientMetadata.put(Constraints.METADATA_VP_FORMATS, vpFormats);

            // For direct_post.jwt: advertise the ephemeral encryption key and supported algorithms.
            if (ephemeralPublicKey != null) {
                List<Object> keysList = new ArrayList<>();
                keysList.add(ephemeralPublicKey.toJSONObject());
                Map<String, Object> jwks = new HashMap<>();
                jwks.put("keys", keysList);
                clientMetadata.put("jwks", jwks);
                clientMetadata.put("authorization_encrypted_response_alg", "ECDH-ES");
                clientMetadata.put("authorization_encrypted_response_enc", "A256GCM");
            }

            claimsBuilder.claim(Constraints.CLAIM_CLIENT_METADATA, clientMetadata);

            if (StringUtils.isNotBlank(registrationCert)) {
                claimsBuilder.claim("verifier_attestations",
                        Collections.singletonList(registrationCert));
            }

            JWTClaimsSet claims = claimsBuilder.build();

            // --- Serialize: unsigned (PlainJWT) for redirect_uri, signed (JWS) for x509 ---
            if (jwsHeader == null) {
                // redirect_uri scheme: alg:none — unsigned JWT per spec §5.7.
                com.nimbusds.jose.PlainHeader plainHeader = new com.nimbusds.jose.PlainHeader.Builder()
                        .type(new JOSEObjectType(Constraints.JOSE_TYPE_OAUTH_AUTHZ_REQ))
                        .build();
                return new com.nimbusds.jwt.PlainJWT(plainHeader, claims).serialize();
            }

            JWSObject jwsObject = new JWSObject(jwsHeader, new Payload(claims.toJSONObject()));
            jwsObject.sign(jwsSigner);
            return jwsObject.serialize();

        } catch (VPAuthenticatorException e) {
            throw e;
        } catch (Exception e) {
            LOG.error("Error building request object JWT for tenant=" + tenantDomain, e);
            throw new VPAuthenticatorServerException(
                    VPAuthenticatorErrorCode.SIGNING_ERROR,
                    "Error building request object JWT.", e);
        }
    }

    /**
     * Build a DCQL (Digital Credentials Query Language) query from a {@link PresentationDefinition}.
     * Each requested credential becomes one DCQL credential entry.
     */
    private Map<String, Object> buildDcqlQuery(PresentationDefinition pd) {

        List<Map<String, Object>> credentials = new ArrayList<>();

        if (pd != null && pd.getRequestedCredentials() != null) {
            int index = 1;
            for (PresentationDefinition.RequestedCredential cred : pd.getRequestedCredentials()) {
                if (cred == null) {
                    continue;
                }

                Map<String, Object> dcqlCred = new HashMap<>();
                String credType = cred.getType() != null ? cred.getType() : "";
                // DCQL credential IDs must match [A-Za-z0-9_-]+
                String credId = credType.isEmpty()
                        ? "credential_" + index
                        : credType.toLowerCase(Locale.ENGLISH).replaceAll("[^A-Za-z0-9_-]", "_") + "_" + index;
                dcqlCred.put("id", credId);
                dcqlCred.put("format", "dc+sd-jwt");

                if (!credType.isEmpty()) {
                    Map<String, Object> meta = new HashMap<>();
                    meta.put("vct_values", Collections.singletonList(credType));
                    dcqlCred.put("meta", meta);
                }

                List<Map<String, Object>> claimsList = new ArrayList<>();
                if (cred.getClaims() != null) {
                    for (PresentationDefinition.ClaimConstraint constraint : cred.getClaims()) {
                        if (constraint == null || StringUtils.isBlank(constraint.getName())) {
                            continue;
                        }
                        String claimName = constraint.getName();
                        Map<String, Object> claim = new HashMap<>();
                        claim.put("id", claimName);
                        claim.put("path", Collections.singletonList(claimName));
                        claimsList.add(claim);
                    }
                }

                if (!claimsList.isEmpty()) {
                    dcqlCred.put("claims", claimsList);
                }
                credentials.add(dcqlCred);
                index++;
            }
        }

        // credential_sets groups credentials into required combinations (Thunder/EUDI ARF pattern).
        List<String> credentialIds = new ArrayList<>();
        for (Map<String, Object> cred : credentials) {
            Object id = cred.get("id");
            if (id instanceof String) {
                credentialIds.add((String) id);
            }
        }

        Map<String, Object> dcql = new HashMap<>();
        dcql.put("credentials", credentials);
        if (!credentialIds.isEmpty()) {
            Map<String, Object> credSet = new HashMap<>();
            credSet.put("options", Collections.singletonList(credentialIds));
            dcql.put("credential_sets", Collections.singletonList(credSet));
        }
        return dcql;
    }

    private char[] resolveKeyPassword(KeyStoreManager ksm, String tenantDomain) throws VPAuthenticatorException {

        if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            String pwd = ServerConfiguration.getInstance().getFirstProperty("Security.KeyStore.KeyPassword");
            return pwd != null ? pwd.toCharArray() : new char[0];
        }
        try {
            char[] pwd = ksm.getPrivateKeyPassword(tenantDomain.replace(".", "-") + ".jks");
            return pwd != null ? pwd : new char[0];
        } catch (CarbonException e) {
            throw new VPAuthenticatorServerException(
                    VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to retrieve keystore password for tenant: " + tenantDomain, e);
        }
    }
}
