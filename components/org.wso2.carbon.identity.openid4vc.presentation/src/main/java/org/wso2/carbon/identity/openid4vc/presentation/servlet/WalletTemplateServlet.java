package org.wso2.carbon.identity.openid4vc.presentation.servlet;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet to expose presentation templates to wallets via GET request.
 * Endpoint: /wallet-callback/template?client_id=xxx&version=current&state=yyy
 *
 * This is a placeholder implementation that returns a default template.
 * For production, integrate with PresentationTemplateService.
 */
public class WalletTemplateServlet extends HttpServlet {

    private static final Log log = LogFactory.getLog(WalletTemplateServlet.class);
    private static final String PARAM_CLIENT_ID = "client_id";
    private static final String PARAM_VERSION = "version";
    private static final String PARAM_STATE = "state";

    private final Gson gson = new Gson();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {

        response.setContentType("application/json");

        // Enable CORS for wallet access
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type");

        String clientId = request.getParameter(PARAM_CLIENT_ID);
        String version = request.getParameter(PARAM_VERSION);
        String state = request.getParameter(PARAM_STATE);

        // Validate required parameter
        if (clientId == null || clientId.trim().isEmpty()) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "missing_parameter", "client_id parameter is required");
            return;
        }

        // Use default version if not provided
        if (version == null || version.trim().isEmpty()) {
            version = "current";
        }

        try {
            if (log.isDebugEnabled()) {
                log.debug("Template request - client_id: " + clientId + ", version: " + version);
            }

            // Build default template JSON
            JsonObject templateJson = buildDefaultTemplate();

            // Add runtime parameters if state is provided
            if (state != null && !state.trim().isEmpty()) {
                templateJson.addProperty(PARAM_STATE, state);
            }

            // Send success response
            response.setStatus(HttpServletResponse.SC_OK);
            PrintWriter out = response.getWriter();
            out.print(gson.toJson(templateJson));
            out.flush();

            if (log.isDebugEnabled()) {
                log.debug("Template retrieved successfully for client: " + clientId);
            }

        } catch (Exception e) {
            log.error("Error retrieving presentation template", e);
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "server_error", "Failed to retrieve template");
        }
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) {
        // Handle CORS preflight
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type");
        response.setStatus(HttpServletResponse.SC_OK);
    }

    /**
     * Builds a default OpenID4VP presentation template.
     *
     * @return Default template JSON object
     */
    private JsonObject buildDefaultTemplate() {
        JsonObject template = new JsonObject();
        template.addProperty("client_id_prefix", "redirect_uri:");

        // Accepted formats
        com.google.gson.JsonArray formats = new com.google.gson.JsonArray();
        formats.add("jwt_vc_json");
        formats.add("dc+sd-jwt");
        template.add("accepted_formats", formats);

        template.addProperty("response_mode", "direct_post");

        // DCQL structure
        JsonObject dcql = new JsonObject();
        com.google.gson.JsonArray credentials = new com.google.gson.JsonArray();

        JsonObject credential = new JsonObject();
        credential.addProperty("id", "identity_credential");
        credential.addProperty("format", "jwt_vc_json");

        com.google.gson.JsonArray claimsPathPointers = new com.google.gson.JsonArray();
        JsonObject pathPointer = new JsonObject();
        pathPointer.addProperty("path", "$.vc.credentialSubject.email");
        claimsPathPointers.add(pathPointer);

        credential.add("claims_path_pointers", claimsPathPointers);
        credentials.add(credential);

        dcql.add("credentials", credentials);
        template.add("dcql", dcql);

        // Metadata
        JsonObject metadata = new JsonObject();
        metadata.addProperty("nonce_required", true);
        template.add("metadata", metadata);

        return template;
    }

    private void sendErrorResponse(HttpServletResponse response, int statusCode,
                                   String error, String description) throws IOException {
        response.setStatus(statusCode);
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("error", error);
        errorResponse.put("error_description", description);

        PrintWriter out = response.getWriter();
        out.print(gson.toJson(errorResponse));
        out.flush();
    }
}


