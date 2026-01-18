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

package org.wso2.carbon.identity.openid4vc.presentation.service.impl;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.exception.DIDDocumentException;
import org.wso2.carbon.identity.openid4vc.presentation.model.DIDDocument;
import org.wso2.carbon.identity.openid4vc.presentation.service.DIDDocumentService;
import org.wso2.carbon.identity.openid4vc.presentation.util.DIDKeyManager;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of DIDDocumentService.
 * Generates and manages DID Documents for WSO2 Identity Server using did:web method.
 */
public class DIDDocumentServiceImpl implements DIDDocumentService {

    private static final Log LOG = LogFactory.getLog(DIDDocumentServiceImpl.class);
    private static final Gson GSON = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .create();

    private static final String DID_CONTEXT_V1 = "https://www.w3.org/ns/did/v1";
    private static final String JWS_2020_CONTEXT = "https://w3id.org/security/suites/jws-2020/v1";

    @Override
    public String getDIDDocument(String domain, int tenantId) throws DIDDocumentException {
        DIDDocument doc = getDIDDocumentObject(domain, tenantId);
        return convertToJson(doc);
    }

    @Override
    public DIDDocument getDIDDocumentObject(String domain, int tenantId) throws DIDDocumentException {
        try {
            LOG.debug("Generating DID document for domain: " + domain + ", tenant: " + tenantId);

            // Get or generate keys
            KeyPair keyPair = DIDKeyManager.getOrGenerateKeyPair(tenantId);

            // Build DID
            String did = getDID(domain);

            // Create DID Document
            DIDDocument doc = new DIDDocument();
            doc.setId(did);
            
            // Set context
            doc.setContext(Arrays.asList(DID_CONTEXT_V1, JWS_2020_CONTEXT));

            // Create verification method
            DIDDocument.VerificationMethod vm = new DIDDocument.VerificationMethod();
            vm.setId(did + "#key-1");
            vm.setType("JsonWebKey2020");
            vm.setController(did);

            // Convert public key to JWK
            Map<String, Object> jwk = DIDKeyManager.publicKeyToJWK(keyPair, "key-1");
            vm.setPublicKeyJwkMap(jwk);
            vm.setPublicKeyJwk(DIDKeyManager.jwkToJson(jwk));

            doc.setVerificationMethod(Arrays.asList(vm));

            // Set verification relationships
            doc.setAuthentication(Arrays.asList(did + "#key-1"));
            doc.setAssertionMethod(Arrays.asList(did + "#key-1"));

            LOG.info("DID document generated successfully for: " + did);
            return doc;

        } catch (Exception e) {
            String errorMsg = "Failed to generate DID document for domain: " + domain;
            LOG.error(errorMsg, e);
            throw new DIDDocumentException(errorMsg, e);
        }
    }

    @Override
    public String getDID(String domain) {
        // Clean domain: remove protocol, port encoding for did:web
        String cleanDomain = domain.replace("https://", "").replace("http://", "");
        
        // For did:web, port numbers are encoded with %3A
        cleanDomain = cleanDomain.replace(":", "%3A");
        
        return "did:web:" + cleanDomain;
    }

    @Override
    public String regenerateKeys(String domain, int tenantId) throws DIDDocumentException {
        try {
            LOG.info("Regenerating keys for domain: " + domain + ", tenant: " + tenantId);
            DIDKeyManager.regenerateKeyPair(tenantId);
            return getDIDDocument(domain, tenantId);
        } catch (Exception e) {
            String errorMsg = "Failed to regenerate keys for domain: " + domain;
            LOG.error(errorMsg, e);
            throw new DIDDocumentException(errorMsg, e);
        }
    }

    @Override
    public boolean hasKeys(int tenantId) {
        return DIDKeyManager.hasKeys(tenantId);
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
        
        jsonMap.put("@context", doc.getContext());
        jsonMap.put("id", doc.getId());

        if (doc.getController() != null) {
            jsonMap.put("controller", doc.getController());
        }

        if (doc.getAlsoKnownAs() != null && !doc.getAlsoKnownAs().isEmpty()) {
            jsonMap.put("alsoKnownAs", doc.getAlsoKnownAs());
        }

        // Verification methods
        if (doc.getVerificationMethod() != null && !doc.getVerificationMethod().isEmpty()) {
            java.util.List<Map<String, Object>> vmList = new ArrayList<>();
            for (DIDDocument.VerificationMethod vm : doc.getVerificationMethod()) {
                Map<String, Object> vmMap = new HashMap<>();
                vmMap.put("id", vm.getId());
                vmMap.put("type", vm.getType());
                vmMap.put("controller", vm.getController());
                
                if (vm.getPublicKeyJwkMap() != null) {
                    vmMap.put("publicKeyJwk", vm.getPublicKeyJwkMap());
                } else if (vm.getPublicKeyMultibase() != null) {
                    vmMap.put("publicKeyMultibase", vm.getPublicKeyMultibase());
                } else if (vm.getPublicKeyBase58() != null) {
                    vmMap.put("publicKeyBase58", vm.getPublicKeyBase58());
                }
                
                vmList.add(vmMap);
            }
            jsonMap.put("verificationMethod", vmList);
        }

        // Verification relationships
        if (doc.getAuthentication() != null && !doc.getAuthentication().isEmpty()) {
            jsonMap.put("authentication", doc.getAuthentication());
        }

        if (doc.getAssertionMethod() != null && !doc.getAssertionMethod().isEmpty()) {
            jsonMap.put("assertionMethod", doc.getAssertionMethod());
        }

        if (doc.getKeyAgreement() != null && !doc.getKeyAgreement().isEmpty()) {
            jsonMap.put("keyAgreement", doc.getKeyAgreement());
        }

        if (doc.getCapabilityInvocation() != null && !doc.getCapabilityInvocation().isEmpty()) {
            jsonMap.put("capabilityInvocation", doc.getCapabilityInvocation());
        }

        if (doc.getCapabilityDelegation() != null && !doc.getCapabilityDelegation().isEmpty()) {
            jsonMap.put("capabilityDelegation", doc.getCapabilityDelegation());
        }

        // Services
        if (doc.getService() != null && !doc.getService().isEmpty()) {
            jsonMap.put("service", doc.getService());
        }

        return GSON.toJson(jsonMap);
    }
}
