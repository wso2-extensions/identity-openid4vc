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

package org.wso2.carbon.identity.openid4vc.presentation.server.servlet;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.ECKey;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.server.cache.StandaloneVerificationCache;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.server.internal.VPServerDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.StandaloneVerificationSession;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.VPContext;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.VPSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.PROP_PRESENTATION_DEFINITION_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.RESPONSE_CONTENT_TYPE_CHARSET_UTF_8;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.RESPONSE_ERROR;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.RESPONSE_ERROR_CODE;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.RESPONSE_ERROR_DESCRIPTION;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.RESPONSE_HEADER_VALUE_NOSNIFF;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.SUPER_TENANT_ID_PLACEHOLDER;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.TENANT_DOMAIN_PATTERN;

/**
 * Servlet handling VP (Verifiable Presentation) submissions from wallets.
 *
 * <p>Implements the OpenID4VP direct_post response mode. Processes
 * both JSON and application/x-www-form-urlencoded submissions, notifies
 * status listeners, and provides spec-compliant feedback to the wallet.</p>
 */
@Component(
    service = Servlet.class,
    immediate = true,
    property = {
        "osgi.http.whiteboard.servlet.pattern=/oid4vp/v1/response",
        "osgi.http.whiteboard.servlet.name=OpenID4VPSubmission",
        "osgi.http.whiteboard.servlet.asyncSupported=true"
    }
)
public class VPSubmissionServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Log LOG = LogFactory.getLog(VPSubmissionServlet.class);

    private static final Gson GSON = new GsonBuilder()
            .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .setPrettyPrinting()
            .create();

    private static final int MAX_PARAM_LENGTH = 65536;

    @Override
    public void init() throws ServletException {

        super.init();
    }

    @Override
    protected void doPost(HttpServletRequest request,
            HttpServletResponse response)
            throws IOException {

        if (VPServerDataHolder.getVerificationService() == null) {
            response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED, "OpenID4VP feature is not enabled.");
            return;
        }
        try {
            String body = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);

            VPSubmission submission;
            String jweCompact = extractJweFromBody(body);
            if (jweCompact != null) {
                submission = decryptAndParseJweSubmission(jweCompact);
            } else {
                submission = parseSubmission(body);
            }

            // Handle wallet error responses per OpenID4VP spec section 7.3.
            if (StringUtils.isNotBlank(submission.getError())) {
                LOG.warn("Wallet sent error response: error=" + sanitize(submission.getError())
                        + ", error_description=" + sanitize(submission.getErrorDescription()));
                if (StringUtils.isNotBlank(submission.getRequestId())) {
                    AuthenticationContext errorContext = FrameworkUtils
                            .getAuthenticationContextFromCache(submission.getRequestId());
                    VPContext errorVpContext = getVPContext(errorContext).orElse(null);
                    if (errorVpContext != null) {
                        errorVpContext.setRequestStatus(VPRequestStatus.FAILED);
                        updateVPContext(submission.getRequestId(), errorVpContext);
                    } else {
                        StandaloneVerificationSession standaloneErrorSession =
                                StandaloneVerificationCache.getInstance().get(submission.getRequestId());
                        if (standaloneErrorSession != null) {
                            standaloneErrorSession.setStatus(VPRequestStatus.FAILED);
                            StandaloneVerificationCache.getInstance().put(
                                    submission.getRequestId(), standaloneErrorSession);
                        }
                    }
                }
                sendSuccessResponse(response);
                return;
            }

            if (!validateRequiredSubmissionFields(submission, response)) {
                return;
            }

            AuthenticationContext context = FrameworkUtils
                    .getAuthenticationContextFromCache(submission.getRequestId());

            if (context == null) {
                StandaloneVerificationSession standaloneSession =
                        StandaloneVerificationCache.getInstance().get(submission.getRequestId());
                if (standaloneSession != null) {
                    processStandaloneSubmission(submission, standaloneSession, request, response);
                    return;
                }
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                "Invalid state parameter."));
                return;
            }

            VPContext vpContext = getVPContext(context).orElse(null);
            String expectedDefinitionId = StringUtils.trimToNull(context.getAuthenticatorProperties()
                    .get(PROP_PRESENTATION_DEFINITION_ID));

            if (vpContext == null) {
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                "Invalid state parameter."));
                return;
            }

            try {
                final PresentationSubmission presentationSubmission;
                if (StringUtils.isBlank(submission.getPresentationSubmission())) {
                    // DCQL flow (e.g. Lissi / EUDI ARF wallets): no presentation_submission.
                    presentationSubmission = buildSyntheticSubmission(expectedDefinitionId);
                } else {
                    if (!validatePresentationDefinitionId(expectedDefinitionId,
                            submission.getPresentationSubmission(), response)) {
                        return;
                    }
                    Gson gson = new GsonBuilder()
                            .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                            .create();
                    presentationSubmission = gson
                            .fromJson(submission.getPresentationSubmission(), PresentationSubmission.class);
                }

                // DCQL wallets send vp_token as a JSON object {"credential-id": ["sd-jwt-string"]}.
                // Extract the raw SD-JWT before verifying.
                String resolvedVpToken = StringUtils.isBlank(submission.getPresentationSubmission())
                        ? extractDcqlVpToken(submission.getVpToken())
                        : null;
                if (resolvedVpToken == null) {
                    resolvedVpToken = submission.getVpToken();
                }

                String expectedNonce = vpContext.getNonce();
                VerificationResult verificationResult = VPServerDataHolder
                        .getVerificationService()
                        .verify(
                                presentationSubmission,
                                IdentityTenantUtil.getTenantId(context.getTenantDomain()),
                                resolvedVpToken,
                                expectedNonce);

                if (!verificationResult.isVerified()) {
                    vpContext.setRequestStatus(VPRequestStatus.FAILED);
                    updateVPContext(submission.getRequestId(), vpContext);

                    String errorMsg = "VP verification failed.";
                    if (verificationResult.getErrors() != null && !verificationResult.getErrors().isEmpty()) {
                        errorMsg = "Verification failed: " + String.join(", ", verificationResult.getErrors());
                    }
                    sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                            new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                    errorMsg));
                    return;
                }

                vpContext.setVerificationResult(verificationResult);

                context.setActiveInAThread(false);
                context.setProperty(Constraints.CONTEXT_VP_CONTEXT, vpContext);
                FrameworkUtils.addAuthenticationContextToCache(submission.getRequestId(), context);

                if (verificationResult.getMetadata() != null) {
                    context.setProperty("vp_metadata", verificationResult.getMetadata());
                }
            } catch (VerificationException e) {
                vpContext.setRequestStatus(VPRequestStatus.FAILED);
                updateVPContext(submission.getRequestId(), vpContext);
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                "VP verification failed: " + e.getMessage()));
                return;
            } catch (JsonSyntaxException e) {
                vpContext.setRequestStatus(VPRequestStatus.FAILED);
                updateVPContext(submission.getRequestId(), vpContext);
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                "Invalid presentation_submission format."));
                return;
            }

            updateRequestStatus(submission.getRequestId());
            sendSuccessResponse(response);

        } catch (RuntimeException e) {
            LOG.error("Unexpected error processing VP submission.", e);
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                            "Internal server error.", e));
        }
    }

    private boolean validateRequiredSubmissionFields(VPSubmission submission,
                                                     HttpServletResponse response)
            throws IOException {

        if (StringUtils.isBlank(submission.getRequestId())) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                            "Missing state parameter."));
            return false;
        }

        if (StringUtils.isBlank(submission.getVpToken())) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                            "Missing vp_token."));
            return false;
        }

        return true;
    }

    private boolean validatePresentationDefinitionId(String expectedDefinitionId,
                                                     String presentationSubmissionJson,
                                                     HttpServletResponse response)
            throws IOException {

        String submittedDefinitionId = getSubmittedPresentationDefinitionId(presentationSubmissionJson);

        if (StringUtils.isBlank(expectedDefinitionId)
                || StringUtils.isBlank(submittedDefinitionId)
                || !StringUtils.equals(expectedDefinitionId, submittedDefinitionId)) {

            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                            "Submitted presentation definition does not match the configured definition."));
            return false;
        }

        return true;
    }

    private String getSubmittedPresentationDefinitionId(String presentationSubmissionJson) {

        try {
            JsonObject submissionJson = GSON.fromJson(presentationSubmissionJson, JsonObject.class);
            if (submissionJson == null || !submissionJson.has("definition_id")
                    || submissionJson.get("definition_id").isJsonNull()) {
                return null;
            }
            return StringUtils.trimToNull(submissionJson.get("definition_id").getAsString());
        } catch (JsonSyntaxException | UnsupportedOperationException e) {
            return null;
        }
    }

    private VPSubmission parseSubmission(String body) {

        VPSubmission submission = new VPSubmission();

        if (StringUtils.isNotBlank(body) && body.trim().startsWith("{")) {
            try {
                return GSON.fromJson(body, VPSubmission.class);
            } catch (JsonSyntaxException e) {
                LOG.warn("Failed to parse JSON submission body.");
            }
        } else {
            parseFormEncodedSubmission(body, submission);
        }

        return submission;
    }

    private void parseFormEncodedSubmission(String formBody, VPSubmission submission) {

        submission.setVpToken(getDecodedFormParameter(formBody, OpenID4VPConstants.ResponseParams.VP_TOKEN));
        submission.setPresentationSubmission(getDecodedFormParameter(formBody,
                OpenID4VPConstants.ResponseParams.PRESENTATION_SUBMISSION));
        submission.setRequestId(getDecodedFormParameter(formBody, OpenID4VPConstants.ResponseParams.STATE));
        submission.setError(getDecodedFormParameter(formBody, OpenID4VPConstants.ResponseParams.ERROR));
        submission.setErrorDescription(getDecodedFormParameter(formBody,
                OpenID4VPConstants.ResponseParams.ERROR_DESCRIPTION));
    }

    private String getDecodedFormParameter(String formBody, String paramName) {

        if (!OpenID4VPConstants.ResponseParams.VP_TOKEN.equals(paramName)
                && !OpenID4VPConstants.ResponseParams.PRESENTATION_SUBMISSION.equals(paramName)
                && !OpenID4VPConstants.ResponseParams.STATE.equals(paramName)
                && !OpenID4VPConstants.ResponseParams.ERROR.equals(paramName)
                && !OpenID4VPConstants.ResponseParams.ERROR_DESCRIPTION.equals(paramName)
                && !"response".equals(paramName)) {
            return null;
        }

        String value = null;
        if (StringUtils.isNotBlank(formBody)) {
            String[] pairs = formBody.split("&");
            for (String pair : pairs) {
                String[] keyValue = pair.split("=", 2);
                if (keyValue.length == 0) {
                    continue;
                }
                String key = decodeFormToken(keyValue[0]);
                if (paramName.equals(key)) {
                    value = keyValue.length > 1 ? keyValue[1] : "";
                    break;
                }
            }
        }

        if (StringUtils.isNotBlank(value)) {
            if (value.length() > MAX_PARAM_LENGTH) {
                value = value.substring(0, MAX_PARAM_LENGTH);
            }
            try {
                String decodedValue = URLDecoder.decode(value, StandardCharsets.UTF_8);
                if (OpenID4VPConstants.ResponseParams.VP_TOKEN.equals(paramName)) {
                    String sanitizedValue = decodedValue.trim();

                    if (sanitizedValue.startsWith("\"") && sanitizedValue.endsWith("\"")) {
                        sanitizedValue = sanitizedValue.substring(1, sanitizedValue.length() - 1).trim();
                    }

                    sanitizedValue = StringUtils.strip(sanitizedValue, "\"");

                    if (!StringUtils.equals(decodedValue, sanitizedValue) && LOG.isDebugEnabled()) {
                        LOG.debug("Sanitized quoted vp_token in decoded request parameter.");
                    }

                    return sanitizedValue;
                }

                return decodedValue;
            } catch (IllegalArgumentException e) {
                return sanitize(value);
            }
        }
        return value;
    }

    private String decodeFormToken(String value) {

        if (value == null) {
            return null;
        }
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return sanitize(value);
        }
    }

    private String sanitize(String input) {

        if (input == null) {
            return "";
        }
        return input.replace('\r', '_').replace('\n', '_')
                .replaceAll("[<>\"']", "_");
    }

    private void updateRequestStatus(String requestId) {

        AuthenticationContext context = FrameworkUtils.getAuthenticationContextFromCache(requestId);
        VPContext vpContext = getVPContext(context).orElse(null);

        if (vpContext != null) {
            vpContext.setRequestStatus(VPRequestStatus.VP_SUBMITTED);
            updateVPContext(requestId, vpContext);
        } else {
            LOG.warn("VPContext not found for request ID; submission status will not be updated.");
        }
    }

    private Optional<VPContext> getVPContext(AuthenticationContext context) {

        if (context == null) {
            return Optional.empty();
        }

        Object vpContextObj = context.getProperty(Constraints.CONTEXT_VP_CONTEXT);
        if (vpContextObj instanceof VPContext) {
            return Optional.of((VPContext) vpContextObj);
        }

        return Optional.empty();
    }

    private void updateVPContext(String contextId, VPContext vpContext) {

        if (StringUtils.isBlank(contextId) || vpContext == null) {
            return;
        }

        AuthenticationContext contextForIdLookup = FrameworkUtils.getAuthenticationContextFromCache(contextId);
        if (contextForIdLookup == null) {
            return;
        }

        String internalContextId = contextForIdLookup.getContextIdentifier();
        String tenantDomain = contextForIdLookup.getTenantDomain();

        // Wrap cache ops in the correct tenant flow so AuthenticationContextCache partitions correctly.
        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);

            AuthenticationContext canonicalContext = null;
            if (StringUtils.isNotBlank(internalContextId) && !internalContextId.equals(contextId)) {
                canonicalContext = FrameworkUtils.getAuthenticationContextFromCache(internalContextId);
            }
            if (canonicalContext == null) {
                canonicalContext = contextForIdLookup;
            }

            canonicalContext.setProperty(Constraints.CONTEXT_VP_CONTEXT, vpContext);

            FrameworkUtils.addAuthenticationContextToCache(contextId, canonicalContext);

            if (StringUtils.isNotBlank(internalContextId) && !internalContextId.equals(contextId)) {
                FrameworkUtils.addAuthenticationContextToCache(internalContextId, canonicalContext);
            }

            String mappedId = (String) canonicalContext.getProperty(Constraints.CONTEXT_VP_MAPPED_ID);
            if (StringUtils.isNotBlank(mappedId) && !mappedId.equals(contextId)
                    && !mappedId.equals(internalContextId)) {
                FrameworkUtils.addAuthenticationContextToCache(mappedId, canonicalContext);
            }
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    private void sendSuccessResponse(HttpServletResponse response) throws IOException {

        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader(RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS, RESPONSE_HEADER_VALUE_NOSNIFF);
        response.setContentLength(0);
        response.getOutputStream().flush();
    }

    private void sendErrorResponse(HttpServletResponse response,
                                   int statusCode,
                                   VPAuthenticatorException exception)
            throws IOException {

        response.setStatus(statusCode);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON
                + RESPONSE_CONTENT_TYPE_CHARSET_UTF_8);
        response.setHeader(RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS, RESPONSE_HEADER_VALUE_NOSNIFF);

        JsonObject errorObj = new JsonObject();
        errorObj.addProperty(RESPONSE_ERROR, sanitize(exception.getOAuth2ErrorCode()));
        errorObj.addProperty(RESPONSE_ERROR_DESCRIPTION, sanitize(exception.getMessage()));
        errorObj.addProperty(RESPONSE_ERROR_CODE, exception.getCode());

        byte[] payload = GSON.toJson(errorObj).getBytes(StandardCharsets.UTF_8);
        response.getOutputStream().write(payload);
        response.getOutputStream().flush();
    }

    private String extractJweFromBody(String body) {

        if (StringUtils.isBlank(body)) {
            return null;
        }
        String responseParam = getDecodedFormParameter(body, "response");
        if (responseParam == null) {
            if (body.trim().startsWith("{")) {
                try {
                    JsonObject obj = JsonParser.parseString(body).getAsJsonObject();
                    if (obj.has("response") && obj.get("response").isJsonPrimitive()) {
                        responseParam = obj.get("response").getAsString();
                    }
                } catch (Exception ignored) {
                }
            }
        }
        if (responseParam != null && responseParam.split("\\.").length == 5) {
            return responseParam;
        }
        return null;
    }

    private VPSubmission decryptAndParseJweSubmission(String jweCompact) {

        VPSubmission submission = new VPSubmission();
        try {
            String requestId = extractKidFromJweHeader(jweCompact);
            if (StringUtils.isBlank(requestId)) {
                LOG.warn("direct_post.jwt: no kid in JWE header; cannot look up ephemeral key.");
                return submission;
            }

            String ephemeralPrivateKeyJwk = null;
            AuthenticationContext context = FrameworkUtils.getAuthenticationContextFromCache(requestId);
            VPContext vpContext = getVPContext(context).orElse(null);
            if (vpContext != null) {
                ephemeralPrivateKeyJwk = vpContext.getEphemeralPrivateKeyJwk();
            } else {
                StandaloneVerificationSession standaloneSession =
                        StandaloneVerificationCache.getInstance().get(requestId);
                if (standaloneSession != null) {
                    ephemeralPrivateKeyJwk = standaloneSession.getEphemeralPrivateKeyJwk();
                }
            }
            if (StringUtils.isBlank(ephemeralPrivateKeyJwk)) {
                LOG.warn("direct_post.jwt: no ephemeral key found for request ID: " + sanitize(requestId));
                return submission;
            }

            ECKey privateKey = ECKey.parse(ephemeralPrivateKeyJwk);
            JWEObject jweObject = JWEObject.parse(jweCompact);
            jweObject.decrypt(new ECDHDecrypter(privateKey));
            String plaintext = jweObject.getPayload().toString();

            JsonObject payload;
            String[] jwtParts = plaintext.split("\\.");
            if (jwtParts.length == 3) {
                byte[] claimsBytes = java.util.Base64.getUrlDecoder().decode(jwtParts[1]);
                payload = JsonParser.parseString(new String(claimsBytes, StandardCharsets.UTF_8))
                        .getAsJsonObject();
            } else {
                payload = JsonParser.parseString(plaintext).getAsJsonObject();
            }
            if (payload.has("vp_token")) {
                JsonElement vpTokenElem = payload.get("vp_token");
                submission.setVpToken(vpTokenElem.isJsonPrimitive()
                        ? vpTokenElem.getAsString()
                        : vpTokenElem.toString());
            }
            if (payload.has("presentation_submission")) {
                submission.setPresentationSubmission(payload.get("presentation_submission").toString());
            }
            if (payload.has("state") && payload.get("state").isJsonPrimitive()) {
                submission.setRequestId(payload.get("state").getAsString());
            } else {
                submission.setRequestId(requestId);
            }
            if (payload.has("error") && payload.get("error").isJsonPrimitive()) {
                submission.setError(payload.get("error").getAsString());
            }
            if (payload.has("error_description") && payload.get("error_description").isJsonPrimitive()) {
                submission.setErrorDescription(payload.get("error_description").getAsString());
            }
        } catch (Exception e) {
            LOG.error("Failed to decrypt or parse direct_post.jwt JWE response.", e);
        }
        return submission;
    }

    private String extractKidFromJweHeader(String jweCompact) {

        try {
            String[] parts = jweCompact.split("\\.");
            if (parts.length != 5) {
                return null;
            }
            byte[] headerBytes = java.util.Base64.getUrlDecoder().decode(parts[0]);
            JsonObject header = JsonParser.parseString(
                    new String(headerBytes, StandardCharsets.UTF_8)).getAsJsonObject();
            return header.has("kid") ? header.get("kid").getAsString() : null;
        } catch (Exception e) {
            LOG.warn("Failed to extract kid from JWE header.", e);
            return null;
        }
    }

    private String extractDcqlVpToken(String rawVpToken) {

        if (StringUtils.isBlank(rawVpToken) || !rawVpToken.trim().startsWith("{")) {
            return null;
        }
        try {
            JsonObject obj = JsonParser.parseString(rawVpToken).getAsJsonObject();
            for (String key : obj.keySet()) {
                JsonElement elem = obj.get(key);
                if (elem.isJsonArray()) {
                    JsonArray arr = elem.getAsJsonArray();
                    if (arr.size() > 0 && arr.get(0).isJsonPrimitive()) {
                        return arr.get(0).getAsString();
                    }
                } else if (elem.isJsonPrimitive()) {
                    return elem.getAsString();
                }
            }
        } catch (Exception e) {
            LOG.warn("Failed to parse DCQL vp_token JSON; using raw value.", e);
        }
        return null;
    }

    private void processStandaloneSubmission(VPSubmission submission,
                                             StandaloneVerificationSession session,
                                             HttpServletRequest request,
                                             HttpServletResponse response) throws IOException {

        String requestId = submission.getRequestId();
        String expectedDefinitionId = session.getPresentationDefinitionId();

        try {
            final PresentationSubmission presentationSubmission;
            if (StringUtils.isBlank(submission.getPresentationSubmission())) {
                presentationSubmission = buildSyntheticSubmission(expectedDefinitionId);
            } else {
                if (!validatePresentationDefinitionId(expectedDefinitionId,
                        submission.getPresentationSubmission(), response)) {
                    return;
                }
                Gson gson = new GsonBuilder()
                        .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                        .create();
                presentationSubmission = gson.fromJson(
                        submission.getPresentationSubmission(), PresentationSubmission.class);
            }

            String resolvedVpToken = StringUtils.isBlank(submission.getPresentationSubmission())
                    ? extractDcqlVpToken(submission.getVpToken())
                    : null;
            if (resolvedVpToken == null) {
                resolvedVpToken = submission.getVpToken();
            }

            String expectedNonce = session.getNonce();
            VerificationResult verificationResult = VPServerDataHolder
                    .getVerificationService()
                    .verify(presentationSubmission, session.getTenantId(), resolvedVpToken,
                            expectedNonce);

            if (!verificationResult.isVerified()) {
                session.setStatus(VPRequestStatus.FAILED);
                StandaloneVerificationCache.getInstance().put(requestId, session);
                String errorMsg = "VP verification failed.";
                if (verificationResult.getErrors() != null && !verificationResult.getErrors().isEmpty()) {
                    errorMsg = "Verification failed: " + String.join(", ", verificationResult.getErrors());
                }
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST, errorMsg));
                return;
            }

            session.setVerificationResult(verificationResult);
            session.setStatus(VPRequestStatus.VERIFIED);
            StandaloneVerificationCache.getInstance().put(requestId, session);

        } catch (VerificationException e) {
            session.setStatus(VPRequestStatus.FAILED);
            StandaloneVerificationCache.getInstance().put(requestId, session);
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                            "VP verification failed: " + e.getMessage()));
            return;
        } catch (JsonSyntaxException e) {
            session.setStatus(VPRequestStatus.FAILED);
            StandaloneVerificationCache.getInstance().put(requestId, session);
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                            "Invalid presentation_submission format."));
            return;
        }

        sendSuccessResponse(response);
    }

    private PresentationSubmission buildSyntheticSubmission(String definitionId) {

        PresentationSubmission submission = new PresentationSubmission();
        submission.setDefinitionId(definitionId);

        PresentationSubmission.DescriptorMap descriptor = new PresentationSubmission.DescriptorMap();
        descriptor.setId("dc_credential");
        descriptor.setFormat("dc+sd-jwt");
        descriptor.setPath("$");

        submission.setDescriptorMap(java.util.Collections.singletonList(descriptor));
        return submission;
    }
}
