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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator;

import com.google.gson.JsonObject;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.encoder.Encode;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.VPContext;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints;
import org.wso2.carbon.identity.openid4vc.presentation.server.util.VPAuthenticatorUtil;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.AUTHENTICATOR_FRIENDLY_NAME;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.DISPLAY_ORDER_3;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.PARAM_CLIENT_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.PARAM_REQUEST_URI;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.PARAM_SESSION_DATA_KEY;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.PARAM_STATUS;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.PARAM_VP_REQUEST_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.PROP_PRESENTATION_DEFINITION_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.PROP_TIMEOUT_SECONDS;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.STATUS_FAILED;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.STATUS_SUCCESS;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.WALLET_LOGIN_PAGE;

/**
 * OpenID for Verifiable Presentations (OpenID4VP) authenticator for WSO2 Identity Server.
 *
 * <p>This authenticator implements the OpenID for Verifiable Presentations (OpenID4VP) protocol
 * to authenticate users by verifying their verifiable credentials from a digital wallet.</p>
 */
public class OpenID4VPAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    /**
     * Serial version UID.
     */
    @java.io.Serial
    private static final long serialVersionUID = 1L;

    private static final Log log = LogFactory.getLog(OpenID4VPAuthenticator.class);

    @Override
    public String getName() {

        return AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Initiate the authentication request to the wallet.
     *
     * @param request  HTTP request.
     * @param response HTTP response.
     * @param context  Authentication context.
     * @throws AuthenticationFailedException If request initiation fails.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationContext context)
            throws AuthenticationFailedException {

        if (!Boolean.parseBoolean(IdentityUtil.getProperty("OpenID4VP.Enabled"))) {
            throw new AuthenticationFailedException(
                    "OpenID4VP feature is disabled. Enable it via [openid4vp] enabled=true in deployment.toml.");
        }

        try {
            // Generate a random UUID as the public Request ID.
            String requestId = UUID.randomUUID().toString();
            context.setProperty(Constraints.CONTEXT_VP_CONTEXT,
                    new VPContext(VPRequestStatus.ACTIVE));

            // For sub-org flows, resolve and cache the sub-org's own tenant domain so that
            // VPRequestServiceImpl uses the correct presentation definitions and signing key.
            String orgId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getOrganizationId();
            if (StringUtils.isNotBlank(orgId)) {
                OrganizationManager orgManager = VPServiceDataHolder.getOrganizationManager();
                if (orgManager != null) {
                    try {
                        String orgTenantDomain = orgManager.resolveTenantDomain(orgId);
                        if (StringUtils.isNotBlank(orgTenantDomain)) {
                            context.setProperty(Constraints.CONTEXT_EFFECTIVE_TENANT_DOMAIN, orgTenantDomain);
                        }
                    } catch (OrganizationManagementException e) {
                        log.warn("[OID4VP] Failed to resolve tenant domain for org " + orgId
                                + "; falling back to root tenant.", e);
                    }
                }
            }

            String redirectUrl = createRedirectURI(requestId, context);

            response.sendRedirect(redirectUrl);

            // Cache the authentication context.
            FrameworkUtils.addAuthenticationContextToCache(requestId, context);

        } catch (VPAuthenticatorException e) {
            throw new AuthenticationFailedException("Failed to initiate VP request: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Failed to redirect to login page", e);
        }
    }

    /**
     * Process the authentication response from the wallet.
     *
     * @param request  HTTP request.
     * @param response HTTP response.
     * @param context  Authentication context.
     * @throws AuthenticationFailedException If authentication fails.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {

        Optional<VPContext> vpContextOpt = getVPContext(context);

        VPContext vpContext = vpContextOpt
                .orElseThrow(() -> new AuthenticationFailedException(
                        "No VP request context found in authentication context."));

        VerificationResult verificationResult = vpContext.getVerificationResult();
        if (verificationResult == null || MapUtils.isEmpty(verificationResult.getVerifiedClaims())) {
            throw new AuthenticationFailedException("No verified claims found in context. "
                    + "Verification must have failed.");
        }

        Map<String, Object> verifiedClaims = verificationResult.getVerifiedClaims();

        // Clean up using the best available context cache key.
        String cacheKey = StringUtils.trimToNull(request.getParameter(PARAM_SESSION_DATA_KEY));
        if (StringUtils.isNotBlank(cacheKey)) {
            FrameworkUtils.removeAuthenticationContextFromCache(cacheKey);
        }

        String subjectClaimName = resolveSubjectClaimNameFromIdP(context.getExternalIdP());
        String defaultSubject = resolveSubjectFromClaims(subjectClaimName, verifiedClaims);

        String idpName = context.getExternalIdP() != null
                ? context.getExternalIdP().getIdPName() : null;

        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createFederateAuthenticatedUserFromSubjectIdentifier(defaultSubject, idpName);
        authenticatedUser.setTenantDomain(context.getTenantDomain());

        Map<String, String> remoteToLocalClaimUri = buildRemoteToLocalClaimUriMap(context);

        Map<ClaimMapping, String> rawAttributes = new HashMap<>();
        for (Map.Entry<String, Object> entry : verifiedClaims.entrySet()) {
            if (entry.getValue() != null && StringUtils.isNotBlank(entry.getValue().toString())) {
                String remoteClaim = entry.getKey();
                String claimValue = entry.getValue().toString();
                String localClaimUri = remoteToLocalClaimUri.getOrDefault(remoteClaim, remoteClaim);
                rawAttributes.put(ClaimMapping.build(localClaimUri, remoteClaim, null, false), claimValue);
            }
        }

        if (!rawAttributes.isEmpty()) {
            authenticatedUser.setUserAttributes(rawAttributes);
        }

        context.setSubject(authenticatedUser);
        log.warn("[OID4VP-DEBUG] processAuthenticationResponse complete: subject=" + defaultSubject
                + " | contextTenantDomain=" + context.getTenantDomain()
                + " | effectiveTenantDomain=" + context.getProperty(
                        org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints
                                .CONTEXT_EFFECTIVE_TENANT_DOMAIN)
                + " | orgId=" + PrivilegedCarbonContext.getThreadLocalCarbonContext().getOrganizationId());
    }

    /**
     * Builds a lookup map of remote-claim-URI → local-claim-URI from the IdP's configured claim mappings.
     * This lets the authenticator set the correct WSO2 local claim URI (e.g.
     * {@code http://wso2.org/claims/emailaddress}) as the local side of each {@link ClaimMapping}, so
     * that {@code JITProvisioningPostAuthenticationHandler} can locate the key it needs
     * ({@code EMAIL_ADDRESS_CLAIM}) for existing-user association without a separate ClaimHandler pass.
     * Falls back to the raw remote claim name for any claim not covered by the IdP mappings.
     */
    private Map<String, String> buildRemoteToLocalClaimUriMap(AuthenticationContext context) {

        Map<String, String> remoteToLocal = new HashMap<>();
        if (context.getExternalIdP() == null
                || context.getExternalIdP().getIdentityProvider() == null
                || context.getExternalIdP().getIdentityProvider().getClaimConfig() == null) {
            return remoteToLocal;
        }
        ClaimMapping[] idpClaimMappings = context.getExternalIdP().getIdentityProvider()
                .getClaimConfig().getClaimMappings();
        if (idpClaimMappings == null || idpClaimMappings.length == 0) {
            return remoteToLocal;
        }
        for (ClaimMapping cm : idpClaimMappings) {
            if (cm.getRemoteClaim() != null && cm.getLocalClaim() != null
                    && StringUtils.isNotBlank(cm.getRemoteClaim().getClaimUri())
                    && StringUtils.isNotBlank(cm.getLocalClaim().getClaimUri())) {
                remoteToLocal.put(cm.getRemoteClaim().getClaimUri(), cm.getLocalClaim().getClaimUri());
            }
        }
        return remoteToLocal;
    }

    /**
     * Returns the remote VP claim name configured as the Subject Attribute on the IdP's Attributes tab.
     * WSO2 IS stores this directly as the remote claim name in claimConfig.userClaimURI —
     * no local-to-remote mapping walk needed.
     */
    private String resolveSubjectClaimNameFromIdP(ExternalIdPConfig externalIdPConfig) {

        if (externalIdPConfig == null
                || externalIdPConfig.getIdentityProvider() == null
                || externalIdPConfig.getIdentityProvider().getClaimConfig() == null) {
            return null;
        }
        return externalIdPConfig.getIdentityProvider().getClaimConfig().getUserClaimURI();
    }

    /**
     * Resolve the subject identifier from verified claims.
     *
     * Priority:
     * 1. The claim named by {@code configuredClaimName} (if non-blank and present in claims).
     * 2. The {@code sub} claim (standard SD-JWT subject).
     * 3. The first non-blank claim value from the disclosed claim set.
     * 4. A random UUID as a last resort.
     *
     * @param configuredClaimName Claim name configured on the authenticator (may be blank).
     * @param verifiedClaims      Claims disclosed by the VP token.
     * @return A non-null subject string.
     */
    private String resolveSubjectFromClaims(String configuredClaimName, Map<String, Object> verifiedClaims) {

        if (StringUtils.isNotBlank(configuredClaimName)) {
            Object value = verifiedClaims.get(configuredClaimName);
            if (value != null && StringUtils.isNotBlank(value.toString())) {
                return value.toString();
            }
        }

        // Fall back to the standard 'sub' claim.
        Object sub = verifiedClaims.get("sub");
        if (sub != null && StringUtils.isNotBlank(sub.toString())) {
            return sub.toString();
        }

        // Use the first non-blank disclosed claim value.
        for (Map.Entry<String, Object> entry : verifiedClaims.entrySet()) {
            if (entry.getValue() != null && StringUtils.isNotBlank(entry.getValue().toString())) {
                return entry.getValue().toString();
            }
        }

        return UUID.randomUUID().toString();
    }

    /**
     * Build wallet login redirect URI with required bootstrap parameters for QR rendering.
     *
     * @param requestId  Masked session data key.
     * @return Redirect URI with encoded query parameters.
     */
    private String createRedirectURI(String requestId, AuthenticationContext context)
            throws VPAuthenticatorException {

        String tenantDomain = context.getTenantDomain();
        String baseUrl = VPAuthenticatorUtil.resolveBaseUrl();
        String requestUri = baseUrl + Constraints.REQUEST_URI_ENDPOINT + requestId;
        String scheme = VPAuthenticatorUtil.resolveClientIdScheme(tenantDomain);
        String clientId = VPAuthenticatorUtil.resolveClientId(scheme, baseUrl, tenantDomain);

        // Resolve organization ID for sub-org login flows.
        String orgId = resolveOrganizationId(context);

        // The root tenant domain is the CarbonContext tenant at auth initiation time (e.g. carbon.super).
        // wallet_login.jsp uses this to build /t/{rootTenant}/o/{orgId}/commonauth so the cookie path matches
        // the OAuth2 authorize URL.
        String rootTenantDomain = StringUtils.defaultString(
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain(), tenantDomain);

        return WALLET_LOGIN_PAGE + "?"
                + PARAM_SESSION_DATA_KEY + "=" + URLEncoder.encode(requestId, StandardCharsets.UTF_8)
                + "&" + PARAM_CLIENT_ID + "="
                + URLEncoder.encode(StringUtils.defaultString(clientId), StandardCharsets.UTF_8)
                + "&" + PARAM_REQUEST_URI + "="
                + URLEncoder.encode(StringUtils.defaultString(requestUri), StandardCharsets.UTF_8)
                + "&" + Constraints.PARAM_TENANT_DOMAIN + "="
                + URLEncoder.encode(StringUtils.defaultString(tenantDomain), StandardCharsets.UTF_8)
                + "&" + Constraints.PARAM_ORG_ID + "="
                + URLEncoder.encode(StringUtils.defaultString(orgId), StandardCharsets.UTF_8)
                + "&" + Constraints.PARAM_ROOT_TENANT_DOMAIN + "="
                + URLEncoder.encode(rootTenantDomain, StandardCharsets.UTF_8);
    }

    private String resolveOrganizationId(AuthenticationContext context) {

        // TenantContextRewriteValve sets accessingOrganizationId (not organizationId) for /t/{tenant}/o/{orgId}/...
        String orgId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getAccessingOrganizationId();
        if (StringUtils.isNotBlank(orgId)) {
            return orgId;
        }
        return StringUtils.trimToEmpty(
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getOrganizationId());
    }

    /**
     * Process the authentication request and status/response callbacks.
     *
     * @param request  HTTP request.
     * @param response HTTP response.
     * @param context  Authentication context.
     * @return Status of the authentication flow.
     * @throws AuthenticationFailedException If authentication fails.
     * @throws LogoutFailedException         If logout fails.
     */
    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        String sessionDataKey = getValidatedParameter(request, PARAM_SESSION_DATA_KEY);
        String status = getValidatedParameter(request, PARAM_STATUS);

        // Check if status is being reported.
        if (StringUtils.isNotBlank(status)) {
            return handleStatusCallback(request, response, context, status);
        }

        return super.process(request, response, context);
    }

    /**
     * Handle status callback from the frontend.
     *
     * @param request  HTTP request.
     * @param response HTTP response.
     * @param context  Authentication context.
     * @param status   Status reported by the frontend.
     * @return Status of the authentication flow.
     * @throws AuthenticationFailedException If callback processing fails.
     */
    private AuthenticatorFlowStatus handleStatusCallback(HttpServletRequest request,
                                                         HttpServletResponse response,
                                                         AuthenticationContext context,
                                                         String status)
            throws AuthenticationFailedException {

        if (STATUS_SUCCESS.equals(status)) {
            processAuthenticationResponse(request, response, context);
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (STATUS_FAILED.equals(status)) {
            context.setRetrying(true);
            throw new AuthenticationFailedException("VP verification failed.");
        }

        return AuthenticatorFlowStatus.INCOMPLETE;
    }

    /**
     * Check if retry authentication is enabled.
     *
     * @return True.
     */
    @Override
    protected boolean retryAuthenticationEnabled() {

        return true;
    }

    /**
     * Get the context identifier.
     *
     * @param request HTTP request.
     * @return Context identifier.
     */
    //ToDo use as the name request_id
    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return StringUtils.trimToNull(getValidatedParameter(request, PARAM_SESSION_DATA_KEY));
    }

    /**
     * Check if the authenticator can handle the request.
     *
     * @param request HTTP request.
     * @return True if can handle.
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        String sessionDataKey = StringUtils.trimToNull(
            getValidatedParameter(request, PARAM_SESSION_DATA_KEY));
        String vpRequestId = StringUtils.trimToNull(
            getValidatedParameter(request, PARAM_VP_REQUEST_ID));
        String status = StringUtils.trimToNull(
            getValidatedParameter(request, PARAM_STATUS));

        // Handle status callbacks.
        if (StringUtils.isNotBlank(status)
                && StringUtils.isNotBlank(sessionDataKey)) {
            return true;
        }

        // Handle VP request callbacks.
        if (!StringUtils.isBlank(vpRequestId)
                && !StringUtils.isBlank(sessionDataKey)) {
            return true;
        }

        return false;
    }

    /**
     * Get configuration properties for the authenticator.
     *
     * @return List of configuration properties.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property presentationDefId = new Property();
        presentationDefId.setName(PROP_PRESENTATION_DEFINITION_ID);
        presentationDefId.setDisplayName("Presentation Definition ID");
        presentationDefId.setDescription(
                "ID of the presentation definition to use for VP requests");
        presentationDefId.setDisplayOrder(1);
        presentationDefId.setRequired(false);
        configProperties.add(presentationDefId);

        Property timeout = new Property();
        timeout.setName(PROP_TIMEOUT_SECONDS);
        timeout.setDisplayName("Timeout (seconds)");
        timeout.setDescription("Timeout for VP requests in seconds");
        timeout.setDisplayOrder(DISPLAY_ORDER_3);
        timeout.setDefaultValue("40");
        timeout.setRequired(false);
        configProperties.add(timeout);

        return configProperties;
    }

    /**
     * Read and validate a request parameter.
     *
     * @param request HTTP request.
     * @param name    Parameter name.
     * @return Validated parameter value, or null.
     */
    private String getValidatedParameter(HttpServletRequest request, String name) {

        String value = request.getParameter(name);
        return StringUtils.isNotBlank(value) ? Encode.forHtml(value) : null;
    }

    private Optional<VPContext> getVPContext(AuthenticationContext context) {

        Object vpContextObj = context.getProperty(Constraints.CONTEXT_VP_CONTEXT);
        if (vpContextObj instanceof VPContext) {
            return Optional.of((VPContext) vpContextObj);
        }

        return Optional.empty();
    }
}
