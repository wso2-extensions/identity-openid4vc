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

package org.wso2.carbon.identity.openid4vc.presentation.servlet;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.dto.ErrorDTO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.PresentationDefinitionNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.PresentationDefinitionServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.util.CORSUtil;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet for managing Presentation Definitions.
 * 
 * Endpoints:
 * - GET /openid4vp/v1/presentation-definitions - List all definitions
 * - GET /openid4vp/v1/presentation-definitions/{id} - Get specific definition
 * - POST /openid4vp/v1/presentation-definitions - Create new definition
 * - PUT /openid4vp/v1/presentation-definitions/{id} - Update definition
 * - DELETE /openid4vp/v1/presentation-definitions/{id} - Delete definition
 */
public class VPDefinitionServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(VPDefinitionServlet.class);

    private static final Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .create();

    private static final int DEFAULT_TENANT_ID = -1234;

    private PresentationDefinitionService presentationDefinitionService;

    @Override
    public void init() throws ServletException {
        super.init();
        this.presentationDefinitionService = new PresentationDefinitionServiceImpl();
    }

    /**
     * Handle GET requests - List or get presentation definitions.
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String pathInfo = request.getPathInfo();
        int tenantId = getTenantId(request);

        try {
            if (StringUtils.isBlank(pathInfo) || "/".equals(pathInfo)) {
                // List all definitions
                handleListDefinitions(request, response, tenantId);
            } else {
                // Get specific definition
                String definitionId = pathInfo.substring(1);
                if (definitionId.contains("/")) {
                    definitionId = definitionId.split("/")[0];
                }
                handleGetDefinition(request, response, definitionId, tenantId);
            }
        } catch (PresentationDefinitionNotFoundException e) {
            sendErrorResponse(request, response, HttpServletResponse.SC_NOT_FOUND,
                    ErrorDTO.ErrorCode.PRESENTATION_DEFINITION_NOT_FOUND, e.getMessage());
        } catch (VPException e) {
            log.error("Error retrieving presentation definition", e);
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error", e);
            sendErrorResponse(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorDTO.ErrorCode.INTERNAL_ERROR, "Internal server error");
        }
    }

    /**
     * Handle POST requests - Create new presentation definition.
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        if (log.isDebugEnabled()) {
            log.debug("Creating new presentation definition");
        }

        try {
            String requestBody = IOUtils.toString(request.getInputStream(), StandardCharsets.UTF_8);

            if (StringUtils.isBlank(requestBody)) {
                sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                        ErrorDTO.ErrorCode.INVALID_REQUEST, "Request body is required");
                return;
            }

            // Parse request
            PresentationDefinitionRequest createRequest;
            try {
                createRequest = gson.fromJson(requestBody, PresentationDefinitionRequest.class);
            } catch (Exception e) {
                sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                        ErrorDTO.ErrorCode.INVALID_REQUEST, "Invalid JSON format");
                return;
            }

            // Validate required fields
            if (StringUtils.isBlank(createRequest.getName())) {
                sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                        ErrorDTO.ErrorCode.INVALID_REQUEST, "name is required");
                return;
            }

            if (StringUtils.isBlank(createRequest.getDefinitionJson())) {
                sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                        ErrorDTO.ErrorCode.INVALID_REQUEST, "definitionJson is required");
                return;
            }

            int tenantId = getTenantId(request);

            // Build definition model
            PresentationDefinition definition = new PresentationDefinition.Builder()
                    .definitionId(createRequest.getDefinitionId())
                    .name(createRequest.getName())
                    .description(createRequest.getDescription())
                    .definitionJson(createRequest.getDefinitionJson())
                    .isDefault(createRequest.isDefault())
                    .tenantId(tenantId)
                    .build();

            // Create
            PresentationDefinition created = presentationDefinitionService
                    .createPresentationDefinition(definition, tenantId);

            // Send response
            sendJsonResponse(request, response, HttpServletResponse.SC_CREATED, toResponseDTO(created));

            if (log.isDebugEnabled()) {
                log.debug("Created presentation definition: " + created.getDefinitionId());
            }

        } catch (VPException e) {
            log.error("Error creating presentation definition", e);
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error", e);
            sendErrorResponse(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorDTO.ErrorCode.INTERNAL_ERROR, "Internal server error");
        }
    }

    /**
     * Handle PUT requests - Update presentation definition.
     */
    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String pathInfo = request.getPathInfo();

        if (StringUtils.isBlank(pathInfo) || "/".equals(pathInfo)) {
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, "Definition ID is required");
            return;
        }

        String definitionId = pathInfo.substring(1);
        if (definitionId.contains("/")) {
            definitionId = definitionId.split("/")[0];
        }

        if (log.isDebugEnabled()) {
            log.debug("Updating presentation definition: " + definitionId);
        }

        try {
            String requestBody = IOUtils.toString(request.getInputStream(), StandardCharsets.UTF_8);

            PresentationDefinitionRequest updateRequest = gson.fromJson(requestBody,
                    PresentationDefinitionRequest.class);

            int tenantId = getTenantId(request);

            // Build updated definition
            PresentationDefinition definition = new PresentationDefinition.Builder()
                    .definitionId(definitionId)
                    .name(updateRequest.getName())
                    .description(updateRequest.getDescription())
                    .definitionJson(updateRequest.getDefinitionJson())
                    .isDefault(updateRequest.isDefault())
                    .tenantId(tenantId)
                    .build();

            // Update
            PresentationDefinition updated = presentationDefinitionService
                    .updatePresentationDefinition(definition, tenantId);

            // Send response
            sendJsonResponse(request, response, HttpServletResponse.SC_OK, toResponseDTO(updated));

        } catch (PresentationDefinitionNotFoundException e) {
            sendErrorResponse(request, response, HttpServletResponse.SC_NOT_FOUND,
                    ErrorDTO.ErrorCode.PRESENTATION_DEFINITION_NOT_FOUND, e.getMessage());
        } catch (VPException e) {
            log.error("Error updating presentation definition", e);
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error", e);
            sendErrorResponse(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorDTO.ErrorCode.INTERNAL_ERROR, "Internal server error");
        }
    }

    /**
     * Handle DELETE requests - Delete presentation definition.
     */
    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String pathInfo = request.getPathInfo();

        if (StringUtils.isBlank(pathInfo) || "/".equals(pathInfo)) {
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, "Definition ID is required");
            return;
        }

        String definitionId = pathInfo.substring(1);
        if (definitionId.contains("/")) {
            definitionId = definitionId.split("/")[0];
        }

        if (log.isDebugEnabled()) {
            log.debug("Deleting presentation definition: " + definitionId);
        }

        try {
            int tenantId = getTenantId(request);

            presentationDefinitionService.deletePresentationDefinition(definitionId, tenantId);

            // Send 204 No Content
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);

        } catch (PresentationDefinitionNotFoundException e) {
            sendErrorResponse(request, response, HttpServletResponse.SC_NOT_FOUND,
                    ErrorDTO.ErrorCode.PRESENTATION_DEFINITION_NOT_FOUND, e.getMessage());
        } catch (VPException e) {
            log.error("Error deleting presentation definition", e);
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error", e);
            sendErrorResponse(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorDTO.ErrorCode.INTERNAL_ERROR, "Internal server error");
        }
    }

    /**
     * Handle list all definitions.
     */
    private void handleListDefinitions(HttpServletRequest request, HttpServletResponse response, int tenantId)
            throws Exception {

        List<PresentationDefinition> definitions = presentationDefinitionService
                .getAllPresentationDefinitions(tenantId);

        JsonObject responseObj = new JsonObject();
        responseObj.addProperty("count", definitions.size());
        responseObj.add("definitions", gson.toJsonTree(
                definitions.stream().map(this::toResponseDTO).toArray()));

        sendJsonResponse(request, response, HttpServletResponse.SC_OK, responseObj);
    }

    /**
     * Handle get specific definition.
     */
    private void handleGetDefinition(HttpServletRequest request, HttpServletResponse response, String definitionId,
            int tenantId) throws Exception {

        PresentationDefinition definition = presentationDefinitionService.getPresentationDefinitionById(definitionId,
                tenantId);

        sendJsonResponse(request, response, HttpServletResponse.SC_OK, toResponseDTO(definition));
    }

    /**
     * Convert model to response DTO.
     */
    private PresentationDefinitionResponseDTO toResponseDTO(PresentationDefinition definition) {
        PresentationDefinitionResponseDTO dto = new PresentationDefinitionResponseDTO();
        dto.setDefinitionId(definition.getDefinitionId());
        dto.setName(definition.getName());
        dto.setDescription(definition.getDescription());
        dto.setDefinitionJson(definition.getDefinitionJson());
        dto.setDefault(definition.isDefault());
        dto.setCreatedAt(definition.getCreatedAt());
        dto.setUpdatedAt(definition.getUpdatedAt());
        return dto;
    }

    /**
     * Handle OPTIONS requests for CORS preflight.
     */
    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        CORSUtil.handlePreflight(request, response);
    }

    /**
     * Send JSON response.
     */
    /**
     * Send JSON response.
     */
    private void sendJsonResponse(HttpServletRequest request, HttpServletResponse response, int statusCode, Object data)
            throws IOException {

        response.setStatus(statusCode);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON + ";charset=UTF-8");
        CORSUtil.addCORSHeaders(request, response);

        try (PrintWriter writer = response.getWriter()) {
            writer.write(gson.toJson(data));
        }
    }

    /**
     * Send error response.
     */
    private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response, int statusCode,
            ErrorDTO.ErrorCode errorCode, String message)
            throws IOException {

        ErrorDTO errorDTO = new ErrorDTO(errorCode, message, null);
        sendJsonResponse(request, response, statusCode, errorDTO);
    }

    /**
     * Get tenant ID from request.
     */
    private int getTenantId(HttpServletRequest request) {
        String tenantHeader = request.getHeader("X-Tenant-Id");
        if (StringUtils.isNotBlank(tenantHeader)) {
            try {
                return Integer.parseInt(tenantHeader);
            } catch (NumberFormatException e) {
                // Fall through to default
            }
        }
        return DEFAULT_TENANT_ID;
    }

    /**
     * Request DTO for creating/updating presentation definitions.
     */
    private static class PresentationDefinitionRequest {

        private String definitionId;
        private String name;
        private String description;
        private String definitionJson;
        private boolean isDefault;

        public String getDefinitionId() {
            return definitionId;
        }

        public String getName() {
            return name;
        }

        public String getDescription() {
            return description;
        }

        public String getDefinitionJson() {
            return definitionJson;
        }

        public boolean isDefault() {
            return isDefault;
        }
    }

    /**
     * Response DTO for presentation definitions.
     */
    private static class PresentationDefinitionResponseDTO {

        private String definitionId;
        private String name;
        private String description;
        private String definitionJson;
        private boolean isDefault;
        private long createdAt;
        private Long updatedAt;

        public void setDefinitionId(String definitionId) {
            this.definitionId = definitionId;
        }

        public void setName(String name) {
            this.name = name;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public void setDefinitionJson(String definitionJson) {
            this.definitionJson = definitionJson;
        }

        public void setDefault(boolean isDefault) {
            this.isDefault = isDefault;
        }

        public void setCreatedAt(long createdAt) {
            this.createdAt = createdAt;
        }

        public void setUpdatedAt(Long updatedAt) {
            this.updatedAt = updatedAt;
        }
    }
}
