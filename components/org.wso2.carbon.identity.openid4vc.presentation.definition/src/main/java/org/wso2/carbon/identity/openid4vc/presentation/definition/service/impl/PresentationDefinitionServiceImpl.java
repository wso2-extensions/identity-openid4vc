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

package org.wso2.carbon.identity.openid4vc.presentation.definition.service.impl;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.PresentationDefinitionNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.common.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.common.util.OpenID4VPUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.util.PresentationDefinitionUtil;
import org.wso2.carbon.identity.openid4vc.presentation.definition.dao.PresentationDefinitionDAO;
import org.wso2.carbon.identity.openid4vc.presentation.definition.dao.impl.PresentationDefinitionDAOImpl;
import org.wso2.carbon.identity.openid4vc.presentation.definition.service.PresentationDefinitionService;

import java.util.List;

/**
 * Implementation of PresentationDefinitionService for managing presentation
 * definitions.
 */
public class PresentationDefinitionServiceImpl implements PresentationDefinitionService {

    private final PresentationDefinitionDAO presentationDefinitionDAO;

    /**
     * Default constructor.
     */
    public PresentationDefinitionServiceImpl() {
        this.presentationDefinitionDAO = new PresentationDefinitionDAOImpl();
    }

    /**
     * Constructor for dependency injection.
     *
     * @param presentationDefinitionDAO The DAO to inject.
     */
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value = "EI_EXPOSE_REP2",
            justification = "Intentional injection of a DAO interface reference for testing/overriding. "
                    + "The interface carries no mutable internal state that the caller could alter.")
    public PresentationDefinitionServiceImpl(PresentationDefinitionDAO presentationDefinitionDAO) {
        this.presentationDefinitionDAO = presentationDefinitionDAO;
    }

    @Override
    public PresentationDefinition createPresentationDefinition(
            PresentationDefinition presentationDefinition, int tenantId) throws VPException {

        // Validate input
        validatePresentationDefinition(presentationDefinition);

        // Validate the JSON structure (now just checking it's valid JSON)
        try {
            com.google.gson.JsonParser.parseString(presentationDefinition.getDefinitionJson());
        } catch (com.google.gson.JsonSyntaxException e) {
            throw new VPException("Invalid presentation definition JSON structure", e);
        }

        // Generate ID if not provided
        String definitionId = presentationDefinition.getDefinitionId();
        if (StringUtils.isBlank(definitionId)) {
            definitionId = OpenID4VPUtil.generateRequestId();
        }

        // Check if ID already exists
        if (presentationDefinitionDAO.presentationDefinitionExists(definitionId, tenantId)) {
            throw new VPException("Presentation definition with ID already exists: " + definitionId);
        }

        PresentationDefinition toCreate = new PresentationDefinition.Builder()
                .definitionId(definitionId)
                .name(presentationDefinition.getName())
                .description(presentationDefinition.getDescription())
                .definitionJson(presentationDefinition.getDefinitionJson())
                .tenantId(tenantId)
                .build();

        // Persist
        presentationDefinitionDAO.createPresentationDefinition(toCreate);

        return toCreate;
    }

    @Override
    public PresentationDefinition getPresentationDefinitionById(String definitionId, int tenantId)
            throws PresentationDefinitionNotFoundException, VPException {

        if (StringUtils.isBlank(definitionId)) {
            throw new VPException("Definition ID is required");
        }

        PresentationDefinition definition = presentationDefinitionDAO.getPresentationDefinitionById(
                definitionId, tenantId);

        if (definition == null) {
            throw new PresentationDefinitionNotFoundException(definitionId);
        }

        return definition;
    }

    @Override
    public PresentationDefinition getPresentationDefinitionByResourceId(String resourceId, int tenantId)
            throws VPException {

        if (StringUtils.isBlank(resourceId)) {
            throw new VPException("Resource ID is required");
        }

        return presentationDefinitionDAO.getPresentationDefinitionByResourceId(resourceId, tenantId);
    }

    @Override
    public List<PresentationDefinition> getAllPresentationDefinitions(int tenantId)
            throws VPException {
        return presentationDefinitionDAO.getAllPresentationDefinitions(tenantId);
    }

    @Override
    public PresentationDefinition updatePresentationDefinition(
            PresentationDefinition presentationDefinition, int tenantId)
            throws PresentationDefinitionNotFoundException, VPException {

        String definitionId = presentationDefinition.getDefinitionId();

        // Verify exists
        PresentationDefinition existing = getPresentationDefinitionById(definitionId, tenantId);

        // Validate JSON if provided (now just checking it's valid JSON)
        if (StringUtils.isNotBlank(presentationDefinition.getDefinitionJson())) {
            try {
                com.google.gson.JsonParser.parseString(presentationDefinition.getDefinitionJson());
            } catch (com.google.gson.JsonSyntaxException e) {
                throw new VPException("Invalid presentation definition JSON structure", e);
            }
        }

        // Build updated definition
        PresentationDefinition toUpdate = new PresentationDefinition.Builder()
                .definitionId(definitionId)
                .name(StringUtils.isNotBlank(presentationDefinition.getName()) ? presentationDefinition.getName()
                        : existing.getName())
                .description(presentationDefinition.getDescription() != null ? presentationDefinition.getDescription()
                        : existing.getDescription())
                .definitionJson(StringUtils.isNotBlank(presentationDefinition.getDefinitionJson())
                        ? presentationDefinition.getDefinitionJson()
                        : existing.getDefinitionJson())
                .resourceId(StringUtils.isNotBlank(presentationDefinition.getResourceId()) 
                        ? presentationDefinition.getResourceId() 
                        : existing.getResourceId())
                .tenantId(tenantId)
                .build();

        // Update
        presentationDefinitionDAO.updatePresentationDefinition(toUpdate);

        return toUpdate;
    }

    @Override
    public void deletePresentationDefinition(String definitionId, int tenantId)
            throws PresentationDefinitionNotFoundException, VPException {

        // Verify exists
        getPresentationDefinitionById(definitionId, tenantId);

        // Delete
        presentationDefinitionDAO.deletePresentationDefinition(definitionId, tenantId);

    }

    @Override
    public boolean presentationDefinitionExists(String definitionId, int tenantId)
            throws VPException {
        return presentationDefinitionDAO.presentationDefinitionExists(definitionId, tenantId);
    }

    @Override
    public boolean validatePresentationDefinition(String definitionJson) throws VPException {
        if (StringUtils.isBlank(definitionJson)) {
            return false;
        }
        try {
            com.google.gson.JsonParser.parseString(definitionJson);
            return true;
        } catch (com.google.gson.JsonSyntaxException e) {
            return false;
        }
    }

    @Override
    public String buildPresentationDefinitionJson(String id, String name, String purpose,
            String[] inputDescriptors) throws VPException {
        return PresentationDefinitionUtil.buildPresentationDefinition(
                id, name, purpose, inputDescriptors);
    }

    /**
     * Validate presentation definition before creation.
     */
    private void validatePresentationDefinition(PresentationDefinition definition)
            throws VPException {

        if (definition == null) {
            throw new VPException("Presentation definition cannot be null");
        }

        if (StringUtils.isBlank(definition.getName())) {
            throw new VPException("Presentation definition name is required");
        }

        if (StringUtils.isBlank(definition.getDefinitionJson())) {
            throw new VPException("Presentation definition JSON is required");
        }
    }

    @Override
    public PresentationDefinition getPresentationDefinitionByName(String name, int tenantId) throws VPException {
        
        if (StringUtils.isBlank(name)) {
            throw new VPException("Presentation definition name is required");
        }

        return presentationDefinitionDAO.getPresentationDefinitionByName(name, tenantId);
    }

    @Override
    public List<InputDescriptorClaimsDTO> getClaimsFromPresentationDefinition(String definitionId, int tenantId)
            throws PresentationDefinitionNotFoundException, VPException {

        PresentationDefinition definition = getPresentationDefinitionById(definitionId, tenantId);
        List<InputDescriptorClaimsDTO> claimsList = new java.util.ArrayList<>();

        try {
            com.google.gson.JsonElement root = com.google.gson.JsonParser.parseString(definition.getDefinitionJson());
            if (!root.isJsonObject()) {
                return claimsList;
            }
            com.google.gson.JsonObject rootObj = root.getAsJsonObject();
            if (!rootObj.has("requested_credentials")) {
                return claimsList;
            }

            com.google.gson.JsonArray credentials = rootObj.getAsJsonArray("requested_credentials");
            for (com.google.gson.JsonElement credElem : credentials) {
                if (!credElem.isJsonObject()) {
                    continue;
                }
                com.google.gson.JsonObject cred = credElem.getAsJsonObject();

                InputDescriptorClaimsDTO dto = new InputDescriptorClaimsDTO();
                dto.setInputDescriptorId(cred.has("type") ? cred.get("type").getAsString() : "unknown");

                List<ClaimDTO> fieldClaims = new java.util.ArrayList<>();

                if (cred.has("requested_claims")) {
                    com.google.gson.JsonArray claims = cred.getAsJsonArray("requested_claims");
                    for (com.google.gson.JsonElement claimElem : claims) {
                        String claimName = claimElem.getAsString();
                        ClaimDTO claim = new ClaimDTO();
                        claim.setName(claimName);
                        // Optional path if not default
                        claim.setPath("$." + claimName);
                        fieldClaims.add(claim);
                    }
                }
                dto.setClaims(fieldClaims);
                claimsList.add(dto);
            }

        } catch (RuntimeException e) {
            throw new VPException("Error parsing presentation definition JSON", e);
        }

        return claimsList;
    }
}
