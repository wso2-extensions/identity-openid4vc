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

package org.wso2.carbon.identity.openid4vc.presentation.did.service.impl;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.did.exception.DIDServerException;
import org.wso2.carbon.identity.openid4vc.presentation.did.model.DIDDocument;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.DIDProvider;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.DIDProviderFactory;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.DIDDocumentService;
import org.wso2.carbon.identity.openid4vc.presentation.did.util.Constraints;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of DIDDocumentService.
 * Generates and manages DID Documents for WSO2 Identity Server using did:key
 * method. The did:key method is self-contained - the public key is encoded
 * directly in the DID identifier.
 */
public class DIDDocumentServiceImpl implements DIDDocumentService {

    private static final Gson GSON = new GsonBuilder()
            .setPrettyPrinting()
            .create();

    private static final String JSON_FIELD_CONTEXT = "@context";
    private static final String JSON_FIELD_ID = "id";
    private static final String JSON_FIELD_CONTROLLER = "controller";
    private static final String JSON_FIELD_ALSO_KNOWN_AS = "alsoKnownAs";
    private static final String JSON_FIELD_VERIFICATION_METHOD = "verificationMethod";
    private static final String JSON_FIELD_TYPE = "type";
    private static final String JSON_FIELD_PUBLIC_KEY_JWK = "publicKeyJwk";
    private static final String JSON_FIELD_PUBLIC_KEY_MULTIBASE = "publicKeyMultibase";
    private static final String JSON_FIELD_PUBLIC_KEY_BASE58 = "publicKeyBase58";
    private static final String JSON_FIELD_AUTHENTICATION = "authentication";
    private static final String JSON_FIELD_ASSERTION_METHOD = "assertionMethod";
    private static final String JSON_FIELD_KEY_AGREEMENT = "keyAgreement";
    private static final String JSON_FIELD_CAPABILITY_INVOCATION = "capabilityInvocation";
    private static final String JSON_FIELD_CAPABILITY_DELEGATION = "capabilityDelegation";
    private static final String JSON_FIELD_SERVICE = "service";

    @Override
    public String getDIDDocument(String domain, int tenantId) throws DIDServerException {

        DIDDocument doc = getDIDDocumentObject(domain, tenantId);
        return convertToJson(doc);
    }

    @Override
    public DIDDocument getDIDDocumentObject(String domain, int tenantId) throws DIDServerException {

        try {
            // Since this method backs the .well-known/did.json endpoint, it implies did:web
            DIDProvider provider = DIDProviderFactory.getProvider(Constraints.METHOD_WEB);
            return provider.getDIDDocument(tenantId, domain);
        } catch (VPException e) {
            String errorMsg = "Failed to generate DID document for tenant: " + tenantId;
            throw DIDServerException.didDocumentError(errorMsg, e);
        }
    }

    @Override
    public String getDID(String domain) {

        try {
            // Default to did:web for domain-based lookup
            DIDProvider provider = DIDProviderFactory.getProvider(Constraints.METHOD_WEB);
            return provider.getDID(MultitenantConstants.SUPER_TENANT_ID, domain);
        } catch (VPException e) {
            return Constraints.DID_WEB_PREFIX + domain.replace(":", "%3A");
        }
    }

    /**
     * Get DID for a specific tenant.
     * 
     * @param tenantId The tenant ID
     * @param tenantDomain The tenant domain
     * @return DID identifier (defaults to did:web)
     * @throws DIDServerException if generation fails
     */
    public String getDID(int tenantId, String tenantDomain) throws DIDServerException {

        try {
            // Default to did:web
            String baseUrl = org.wso2.carbon.identity.openid4vc.presentation.common.util.OpenID4VPUtil
                    .getTenantAwareBaseUrl(tenantDomain);
            DIDProvider provider = DIDProviderFactory.getProvider(Constraints.METHOD_WEB);
            return provider.getDID(tenantId, baseUrl);
        } catch (VPException e) {
            throw DIDServerException.didDocumentError("Failed to generate DID for tenant: " + tenantId, e);
        }
    }



    /**
     * Convert DID Document to JSON string.
     * Uses a custom serialization to match W3C DID spec format.
     * 
     * @param doc DIDDocument object
     * @return JSON string
     */
    private String convertToJson(DIDDocument doc) {

        Map<String, Object> jsonMap = new HashMap<>();

        jsonMap.put(JSON_FIELD_CONTEXT, doc.getContext());
        jsonMap.put(JSON_FIELD_ID, doc.getId());

        if (doc.getController() != null) {
            jsonMap.put(JSON_FIELD_CONTROLLER, doc.getController());
        }

        if (doc.getAlsoKnownAs() != null && !doc.getAlsoKnownAs().isEmpty()) {
            jsonMap.put(JSON_FIELD_ALSO_KNOWN_AS, doc.getAlsoKnownAs());
        }

        // Verification methods
        if (doc.getVerificationMethod() != null && !doc.getVerificationMethod().isEmpty()) {
            java.util.List<Map<String, Object>> vmList = new ArrayList<>();
            for (DIDDocument.VerificationMethod vm : doc.getVerificationMethod()) {
                Map<String, Object> vmMap = new HashMap<>();
                vmMap.put(JSON_FIELD_ID, vm.getId());
                vmMap.put(JSON_FIELD_TYPE, vm.getType());
                vmMap.put(JSON_FIELD_CONTROLLER, vm.getController());

                if (vm.getPublicKeyJwkMap() != null) {
                    vmMap.put(JSON_FIELD_PUBLIC_KEY_JWK, vm.getPublicKeyJwkMap());
                } else if (vm.getPublicKeyMultibase() != null) {
                    vmMap.put(JSON_FIELD_PUBLIC_KEY_MULTIBASE, vm.getPublicKeyMultibase());
                } else if (vm.getPublicKeyBase58() != null) {
                    vmMap.put(JSON_FIELD_PUBLIC_KEY_BASE58, vm.getPublicKeyBase58());
                }

                vmList.add(vmMap);
            }
            jsonMap.put(JSON_FIELD_VERIFICATION_METHOD, vmList);
        }

        // Verification relationships
        if (doc.getAuthentication() != null && !doc.getAuthentication().isEmpty()) {
            jsonMap.put(JSON_FIELD_AUTHENTICATION, doc.getAuthentication());
        }

        if (doc.getAssertionMethod() != null && !doc.getAssertionMethod().isEmpty()) {
            jsonMap.put(JSON_FIELD_ASSERTION_METHOD, doc.getAssertionMethod());
        }

        if (doc.getKeyAgreement() != null && !doc.getKeyAgreement().isEmpty()) {
            jsonMap.put(JSON_FIELD_KEY_AGREEMENT, doc.getKeyAgreement());
        }

        if (doc.getCapabilityInvocation() != null && !doc.getCapabilityInvocation().isEmpty()) {
            jsonMap.put(JSON_FIELD_CAPABILITY_INVOCATION, doc.getCapabilityInvocation());
        }

        if (doc.getCapabilityDelegation() != null && !doc.getCapabilityDelegation().isEmpty()) {
            jsonMap.put(JSON_FIELD_CAPABILITY_DELEGATION, doc.getCapabilityDelegation());
        }

        // Services
        if (doc.getService() != null && !doc.getService().isEmpty()) {
            jsonMap.put(JSON_FIELD_SERVICE, doc.getService());
        }

        return GSON.toJson(jsonMap);
    }
}
