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
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.dto.ErrorDTO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.PresentationDefinitionNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.ApplicationPresentationDefinitionMapping;
import org.wso2.carbon.identity.openid4vc.presentation.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.service.ApplicationPresentationDefinitionMappingService;
import org.wso2.carbon.identity.openid4vc.presentation.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.ApplicationPresentationDefinitionMappingServiceImpl;
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
 * Servlet for managing Presentation Definitions and Application Mappings.
 *
 * Presentation Definition Endpoints:
 * - GET /openid4vp/v1/presentation-definitions - List all definitions
 * - GET /openid4vp/v1/presentation-definitions/{id} - Get specific definition
 * - POST /openid4vp/v1/presentation-definitions - Create new definition
 * - PUT /openid4vp/v1/presentation-definitions/{id} - Update definition
 * - DELETE /openid4vp/v1/presentation-definitions/{id} - Delete definition
 *
 * Application Mapping Endpoints:
 * - GET /openid4vp/v1/presentation-definitions/mapping/{applicationId} - Get mapping for application
 * - POST /openid4vp/v1/presentation-definitions/mapping - Create/update application mapping
 * - DELETE /openid4vp/v1/presentation-definitions/mapping/{applicationId} - Delete application mapping
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
    private ApplicationPresentationDefinitionMappingService mappingService;

    @Override
    public void init() throws ServletException {
        super.init();
        this.presentationDefinitionService = new PresentationDefinitionServiceImpl();
        this.mappingService = new ApplicationPresentationDefinitionMappingServiceImpl();
    }

    /**
     * Handle GET requests - List or get presentation definitions, or get application mappings.
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String pathInfo = request.getPathInfo();
        int tenantId = getTenantId(request);

        if (log.isDebugEnabled()) {
            log.debug("GET request received. PathInfo: " + pathInfo + ", TenantId: " + tenantId);
        }

        try {
            if (StringUtils.isBlank(pathInfo) || "/".equals(pathInfo)) {
                // List all definitions
                if (log.isDebugEnabled()) {
                    log.debug("Listing all presentation definitions for tenant: " + tenantId);
                }
                handleListDefinitions(request, response, tenantId);
            } else if (pathInfo.startsWith("/mapping/")) {
                // Handle application mapping requests
                String applicationId = pathInfo.substring("/mapping/".length());
                if (log.isDebugEnabled()) {
                    log.debug("Getting application mapping for applicationId: " + applicationId + ", tenantId: " + tenantId);
                }
                handleGetApplicationMapping(request, response, applicationId, tenantId);
            } else {
                // Get specific definition
                String definitionId = pathInfo.substring(1);
                if (definitionId.contains("/")) {
                    definitionId = definitionId.split("/")[0];
                }
                if (log.isDebugEnabled()) {
                    log.debug("Getting presentation definition: " + definitionId + ", tenantId: " + tenantId);
                }
                handleGetDefinition(request, response, definitionId, tenantId);
            }
        } catch (PresentationDefinitionNotFoundException e) {
            log.error("Presentation definition not found: " + e.getMessage(), e);
            sendErrorResponse(request, response, HttpServletResponse.SC_NOT_FOUND,
                    ErrorDTO.ErrorCode.PRESENTATION_DEFINITION_NOT_FOUND, e.getMessage());
        } catch (VPException e) {
            log.error("VPException in GET request: " + e.getMessage(), e);
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error in GET request", e);
            sendErrorResponse(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorDTO.ErrorCode.INTERNAL_ERROR, "Internal server error");
        }
    }

    /**
     * Handle POST requests - Create new presentation definition or application mapping.
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String pathInfo = request.getPathInfo();
        int tenantId = getTenantId(request);

        if (log.isDebugEnabled()) {
            log.debug("POST request received. PathInfo: " + pathInfo + ", TenantId: " + tenantId);
        }

        try {
            if ("/mapping".equals(pathInfo)) {
                // Handle application mapping creation/update
                if (log.isDebugEnabled()) {
                    log.debug("Creating/updating application presentation definition mapping");
                }
                handleCreateUpdateApplicationMapping(request, response, tenantId);
            } else {
                // Handle presentation definition creation
                if (log.isDebugEnabled()) {
                    log.debug("Creating new presentation definition");
                }
                handleCreatePresentationDefinition(request, response, tenantId);
            }
        } catch (VPException e) {
            log.error("VPException in POST request: " + e.getMessage(), e);
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error in POST request", e);
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
     * Handle DELETE requests - Delete presentation definition or application mapping.
     */
    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String pathInfo = request.getPathInfo();
        int tenantId = getTenantId(request);

        if (log.isDebugEnabled()) {
            log.debug("DELETE request received. PathInfo: " + pathInfo + ", TenantId: " + tenantId);
        }

        try {
            if (pathInfo != null && pathInfo.startsWith("/mapping/")) {
                // Handle application mapping deletion
                String applicationId = pathInfo.substring("/mapping/".length());
                if (log.isDebugEnabled()) {
                    log.debug("Deleting application mapping for applicationId: " + applicationId + ", tenantId: " + tenantId);
                }
                handleDeleteApplicationMapping(request, response, applicationId, tenantId);
            } else {
                // Handle presentation definition deletion
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
                    log.debug("Deleting presentation definition: " + definitionId + ", tenantId: " + tenantId);
                }
                handleDeletePresentationDefinition(request, response, definitionId, tenantId);
            }
        } catch (PresentationDefinitionNotFoundException e) {
            log.error("Presentation definition not found: " + e.getMessage(), e);
            sendErrorResponse(request, response, HttpServletResponse.SC_NOT_FOUND,
                    ErrorDTO.ErrorCode.PRESENTATION_DEFINITION_NOT_FOUND, e.getMessage());
        } catch (VPException e) {
            log.error("VPException in DELETE request: " + e.getMessage(), e);
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error in DELETE request", e);
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

        List<PresentationDefinitionResponseDTO> responseDTOs = definitions.stream()
                .map(this::toResponseDTO)
                .collect(java.util.stream.Collectors.toList());

        sendJsonResponse(request, response, HttpServletResponse.SC_OK, responseDTOs);
    }

    /**
     * Handle get specific definition.
     */
    private void handleGetDefinition(HttpServletRequest request, HttpServletResponse response, String definitionId,
            int tenantId) throws Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving presentation definition: " + definitionId + " for tenant: " + tenantId);
        }

        PresentationDefinition definition = presentationDefinitionService.getPresentationDefinitionById(definitionId,
                tenantId);

        if (log.isDebugEnabled()) {
            log.debug("Successfully retrieved presentation definition: " + definitionId);
        }

        sendJsonResponse(request, response, HttpServletResponse.SC_OK, toResponseDTO(definition));
    }

    /**
     * Handle get application mapping.
     */
    private void handleGetApplicationMapping(HttpServletRequest request, HttpServletResponse response,
            String applicationId, int tenantId) throws Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving application mapping for applicationId: " + applicationId + ", tenantId: " + tenantId);
        }

        try {
            ApplicationPresentationDefinitionMapping mapping = mappingService
                    .getApplicationMapping(applicationId, tenantId);

            if (mapping != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Found mapping: " + mapping.getApplicationId() + " -> " + mapping.getPresentationDefinitionId());
                }
                sendJsonResponse(request, response, HttpServletResponse.SC_OK, mapping);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("No mapping found for applicationId: " + applicationId + ", tenantId: " + tenantId);
                }
                sendErrorResponse(request, response, HttpServletResponse.SC_NOT_FOUND,
                        ErrorDTO.ErrorCode.PRESENTATION_DEFINITION_NOT_FOUND,
                        "No mapping found for application: " + applicationId);
            }
        } catch (Exception e) {
            log.error("Error retrieving application mapping for applicationId: " + applicationId + ", tenantId: " + tenantId, e);
            throw e;
        }
    }

    /**
     * Handle create/update application mapping.
     */
    private void handleCreateUpdateApplicationMapping(HttpServletRequest request, HttpServletResponse response,
            int tenantId) throws Exception {

        if (log.isDebugEnabled()) {
            log.debug("Processing create/update application mapping request for tenantId: " + tenantId);
        }

        String requestBody = IOUtils.toString(request.getInputStream(), StandardCharsets.UTF_8);

        if (StringUtils.isBlank(requestBody)) {
            log.warn("Empty request body received for application mapping creation/update");
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, "Request body is required");
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("Request body: " + requestBody);
        }

        // Parse request
        ApplicationMappingRequest mappingRequest;
        try {
            mappingRequest = gson.fromJson(requestBody, ApplicationMappingRequest.class);
        } catch (Exception e) {
            log.error("Failed to parse JSON request body: " + requestBody, e);
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, "Invalid JSON format");
            return;
        }

        // Validate required fields
        if (StringUtils.isBlank(mappingRequest.getApplicationId())) {
            log.warn("Missing applicationId in request");
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, "applicationId is required");
            return;
        }

        if (StringUtils.isBlank(mappingRequest.getPresentationDefinitionId())) {
            log.warn("Missing presentationDefinitionId in request for applicationId: " + mappingRequest.getApplicationId());
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, "presentationDefinitionId is required");
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("Creating/updating mapping: " + mappingRequest.getApplicationId() + " -> " +
                     mappingRequest.getPresentationDefinitionId() + " for tenantId: " + tenantId);
        }

        try {
            // Create or update the mapping
            mappingService.mapPresentationDefinitionToApplication(
                    mappingRequest.getApplicationId(),
                    mappingRequest.getPresentationDefinitionId(),
                    tenantId);

            if (log.isDebugEnabled()) {
                log.debug("Successfully created/updated mapping for applicationId: " + mappingRequest.getApplicationId());
            }

            // Send success response
            ApplicationMappingResponse successResponse = new ApplicationMappingResponse();
            successResponse.setMessage("Mapping created successfully");
            sendJsonResponse(request, response, HttpServletResponse.SC_CREATED, successResponse);

        } catch (Exception e) {
            log.error("Error creating/updating application mapping for applicationId: " + mappingRequest.getApplicationId(), e);
            throw e;
        }
    }

    /**
     * Handle delete application mapping.
     */
    private void handleDeleteApplicationMapping(HttpServletRequest request, HttpServletResponse response,
            String applicationId, int tenantId) throws Exception {

        if (log.isDebugEnabled()) {
            log.debug("Deleting application mapping for applicationId: " + applicationId + ", tenantId: " + tenantId);
        }

        try {
            mappingService.removePresentationDefinitionMapping(applicationId, tenantId);

            if (log.isDebugEnabled()) {
                log.debug("Successfully deleted mapping for applicationId: " + applicationId);
            }

            // Send 204 No Content
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);

        } catch (Exception e) {
            log.error("Error deleting application mapping for applicationId: " + applicationId + ", tenantId: " + tenantId, e);
            throw e;
        }
    }

    /**
     * Handle create presentation definition.
     */
    private void handleCreatePresentationDefinition(HttpServletRequest request, HttpServletResponse response,
            int tenantId) throws Exception {

        if (log.isDebugEnabled()) {
            log.debug("Creating new presentation definition for tenantId: " + tenantId);
        }

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
            log.error("Failed to parse presentation definition request JSON", e);
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, "Invalid JSON format");
            return;
        }

        // Validate required fields
        if (StringUtils.isBlank(createRequest.getName())) {
            log.warn("Missing name in presentation definition request");
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, "name is required");
            return;
        }

        if (StringUtils.isBlank(createRequest.getDefinitionJson())) {
            log.warn("Missing definitionJson in presentation definition request");
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, "definitionJson is required");
            return;
        }

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

        if (log.isDebugEnabled()) {
            log.debug("Successfully created presentation definition: " + created.getDefinitionId());
        }

        // Send response
        sendJsonResponse(request, response, HttpServletResponse.SC_CREATED, toResponseDTO(created));
    }

    /**
     * Handle delete presentation definition.
     */
    private void handleDeletePresentationDefinition(HttpServletRequest request, HttpServletResponse response,
            String definitionId, int tenantId) throws Exception {

        if (log.isDebugEnabled()) {
            log.debug("Deleting presentation definition: " + definitionId + ", tenantId: " + tenantId);
        }

        presentationDefinitionService.deletePresentationDefinition(definitionId, tenantId);

        if (log.isDebugEnabled()) {
            log.debug("Successfully deleted presentation definition: " + definitionId);
        }

        // Send 204 No Content
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
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

    /**
     * Request DTO for application mapping operations.
     */
    private static class ApplicationMappingRequest {

        private String applicationId;
        private String presentationDefinitionId;

        public String getApplicationId() {
            return applicationId;
        }

        public String getPresentationDefinitionId() {
            return presentationDefinitionId;
        }
    }

    /**
     * Response DTO for application mapping operations.
     */
    private static class ApplicationMappingResponse {

        private String message;

        public void setMessage(String message) {
            this.message = message;
        }

        public String getMessage() {
            return message;
        }
    }
}
