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

package org.wso2.carbon.identity.openid4vc.presentation.did.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Model class representing a DID Document as per W3C DID Core specification.
 * Contains verification methods and public keys needed for signature
 * verification.
 */
public class DIDDocument {

    // Core fields
    private String id;
    private List<String> context;
    private String controller;
    private List<String> alsoKnownAs;

    // Verification methods
    private List<VerificationMethod> verificationMethod;
    private List<String> authentication;
    private List<String> assertionMethod;
    private List<String> keyAgreement;
    private List<String> capabilityInvocation;
    private List<String> capabilityDelegation;

    // Services
    private List<Service> service;

    // Raw document
    private String rawDocument;
    private Map<String, Object> rawMap;

    /**
     * Default constructor.
     */
    public DIDDocument() {

        this.context = new ArrayList<>();
        this.verificationMethod = new ArrayList<>();
        this.authentication = new ArrayList<>();
        this.assertionMethod = new ArrayList<>();
    }

    /**
     * Inner class representing a verification method (public key).
     */
    public static class VerificationMethod {

        private String id;
        private String type;
        private String controller;
        private String publicKeyJwk; // JSON string of JWK
        private Map<String, Object> publicKeyJwkMap;
        private String publicKeyMultibase;
        private String publicKeyBase58;
        private String publicKeyPem;

        /**
         * Get the ID.
         * 
         * @return The ID
         */
        public String getId() {

            return id;
        }

        /**
         * Set the ID.
         * 
         * @param id The ID
         */
        public void setId(String id) {

            this.id = id;
        }

        /**
         * Get the type.
         * 
         * @return The type
         */
        public String getType() {

            return type;
        }

        /**
         * Set the type.
         * 
         * @param type The type
         */
        public void setType(String type) {

            this.type = type;
        }

        /**
         * Get the controller.
         * 
         * @return The controller
         */
        public String getController() {

            return controller;
        }

        /**
         * Set the controller.
         * 
         * @param controller The controller
         */
        public void setController(String controller) {

            this.controller = controller;
        }

        /**
         * Get the public key JWK.
         * 
         * @return The public key JWK
         */
        public String getPublicKeyJwk() {

            return publicKeyJwk;
        }

        /**
         * Set the public key JWK.
         * 
         * @param publicKeyJwk The public key JWK
         */
        public void setPublicKeyJwk(String publicKeyJwk) {

            this.publicKeyJwk = publicKeyJwk;
        }

        /**
         * Get the public key JWK map.
         * 
         * @return The public key JWK map
         */
        public Map<String, Object> getPublicKeyJwkMap() {

            return publicKeyJwkMap != null ? new HashMap<>(publicKeyJwkMap) : null;
        }

        /**
         * Set the public key JWK map.
         * 
         * @param publicKeyJwkMap The public key JWK map
         */
        public void setPublicKeyJwkMap(Map<String, Object> publicKeyJwkMap) {

            this.publicKeyJwkMap = publicKeyJwkMap != null ? new HashMap<>(publicKeyJwkMap) : null;
        }

        /**
         * Get the public key multibase.
         * 
         * @return The public key multibase
         */
        public String getPublicKeyMultibase() {

            return publicKeyMultibase;
        }

        /**
         * Set the public key multibase.
         * 
         * @param publicKeyMultibase The public key multibase
         */
        public void setPublicKeyMultibase(String publicKeyMultibase) {

            this.publicKeyMultibase = publicKeyMultibase;
        }

        /**
         * Get the public key base58.
         * 
         * @return The public key base58
         */
        public String getPublicKeyBase58() {

            return publicKeyBase58;
        }

        /**
         * Set the public key base58.
         * 
         * @param publicKeyBase58 The public key base58
         */
        public void setPublicKeyBase58(String publicKeyBase58) {

            this.publicKeyBase58 = publicKeyBase58;
        }

        /**
         * Get the public key PEM.
         * 
         * @return The public key PEM
         */
        public String getPublicKeyPem() {

            return publicKeyPem;
        }

        /**
         * Set the public key PEM.
         * 
         * @param publicKeyPem The public key PEM
         */
        public void setPublicKeyPem(String publicKeyPem) {

            this.publicKeyPem = publicKeyPem;
        }

        @Override
        public String toString() {

            return "VerificationMethod{" +
                    "id='" + id + '\'' +
                    ", type='" + type + '\'' +
                    '}';
        }
    }

    /**
     * Inner class representing a DID service endpoint.
     */
    public static class Service {
        
        private String id;
        private String type;
        private String serviceEndpoint;
        private Map<String, Object> serviceEndpointMap;

        /**
         * Get the ID.
         * 
         * @return The ID
         */
        public String getId() {

            return id;
        }

        /**
         * Set the ID.
         * 
         * @param id The ID
         */
        public void setId(String id) {

            this.id = id;
        }

        /**
         * Get the type.
         * 
         * @return The type
         */
        public String getType() {

            return type;
        }

        /**
         * Set the type.
         * 
         * @param type The type
         */
        public void setType(String type) {

            this.type = type;
        }

        /**
         * Get the service endpoint.
         * 
         * @return The service endpoint
         */
        public String getServiceEndpoint() {

            return serviceEndpoint;
        }

        /**
         * Set the service endpoint.
         * 
         * @param serviceEndpoint The service endpoint
         */
        public void setServiceEndpoint(String serviceEndpoint) {

            this.serviceEndpoint = serviceEndpoint;
        }

        /**
         * Get the service endpoint map.
         * 
         * @return The service endpoint map
         */
        public Map<String, Object> getServiceEndpointMap() {

            return serviceEndpointMap != null ? new HashMap<>(serviceEndpointMap) : null;
        }

        /**
         * Set the service endpoint map.
         * 
         * @param serviceEndpointMap The service endpoint map
         */
        public void setServiceEndpointMap(Map<String, Object> serviceEndpointMap) {

            this.serviceEndpointMap = serviceEndpointMap != null ? new HashMap<>(serviceEndpointMap) : null;
        }
    }

    // Getters and Setters

    /**
     * Get the ID.
     * 
     * @return The ID
     */
    public String getId() {

        return id;
    }

    /**
     * Set the ID.
     * 
     * @param id The ID
     */
    public void setId(String id) {

        this.id = id;
    }

    /**
     * Get the context.
     * 
     * @return The context list
     */
    public List<String> getContext() {

        return context != null ? new ArrayList<>(context) : null;
    }

    /**
     * Set the context.
     * 
     * @param context The context list
     */
    public void setContext(List<String> context) {

        this.context = context != null ? new ArrayList<>(context) : null;
    }

    /**
     * Get the controller.
     * 
     * @return The controller
     */
    public String getController() {

        return controller;
    }

    /**
     * Set the controller.
     * 
     * @param controller The controller
     */
    public void setController(String controller) {

        this.controller = controller;
    }

    /**
     * Get also known as.
     * 
     * @return The also known as list
     */
    public List<String> getAlsoKnownAs() {

        return alsoKnownAs != null ? new ArrayList<>(alsoKnownAs) : null;
    }

    /**
     * Set also known as.
     * 
     * @param alsoKnownAs The also known as list
     */
    public void setAlsoKnownAs(List<String> alsoKnownAs) {

        this.alsoKnownAs = alsoKnownAs != null ? new ArrayList<>(alsoKnownAs) : null;
    }

    /**
     * Get the verification methods.
     * 
     * @return The verification methods list
     */
    public List<VerificationMethod> getVerificationMethod() {

        return verificationMethod != null ? new ArrayList<>(verificationMethod) : null;
    }

    /**
     * Set the verification methods.
     * 
     * @param verificationMethod The verification methods list
     */
    public void setVerificationMethod(List<VerificationMethod> verificationMethod) {

        this.verificationMethod = verificationMethod != null ? new ArrayList<>(verificationMethod) : null;
    }

    /**
     * Add a verification method.
     * 
     * @param method The verification method to add
     */
    public void addVerificationMethod(VerificationMethod method) {

        if (this.verificationMethod == null) {
            this.verificationMethod = new ArrayList<>();
        }
        this.verificationMethod.add(method);
    }

    /**
     * Get the authentication methods.
     * 
     * @return The authentication methods list
     */
    public List<String> getAuthentication() {

        return authentication != null ? new ArrayList<>(authentication) : null;
    }

    /**
     * Set the authentication methods.
     * 
     * @param authentication The authentication methods list
     */
    public void setAuthentication(List<String> authentication) {

        this.authentication = authentication != null ? new ArrayList<>(authentication) : null;
    }

    /**
     * Get the assertion methods.
     * 
     * @return The assertion methods list
     */
    public List<String> getAssertionMethod() {

        return assertionMethod != null ? new ArrayList<>(assertionMethod) : null;
    }

    /**
     * Set the assertion methods.
     * 
     * @param assertionMethod The assertion methods list
     */
    public void setAssertionMethod(List<String> assertionMethod) {

        this.assertionMethod = assertionMethod != null ? new ArrayList<>(assertionMethod) : null;
    }

    /**
     * Get the key agreement methods.
     * 
     * @return The key agreement methods list
     */
    public List<String> getKeyAgreement() {

        return keyAgreement != null ? new ArrayList<>(keyAgreement) : null;
    }

    /**
     * Set the key agreement methods.
     * 
     * @param keyAgreement The key agreement methods list
     */
    public void setKeyAgreement(List<String> keyAgreement) {

        this.keyAgreement = keyAgreement != null ? new ArrayList<>(keyAgreement) : null;
    }

    /**
     * Get the capability invocation methods.
     * 
     * @return The capability invocation methods list
     */
    public List<String> getCapabilityInvocation() {

        return capabilityInvocation != null ? new ArrayList<>(capabilityInvocation) : null;
    }

    /**
     * Set the capability invocation methods.
     * 
     * @param capabilityInvocation The capability invocation methods list
     */
    public void setCapabilityInvocation(List<String> capabilityInvocation) {

        this.capabilityInvocation = capabilityInvocation != null ? new ArrayList<>(capabilityInvocation) : null;
    }

    /**
     * Get the capability delegation methods.
     * 
     * @return The capability delegation methods list
     */
    public List<String> getCapabilityDelegation() {

        return capabilityDelegation != null ? new ArrayList<>(capabilityDelegation) : null;
    }

    /**
     * Set the capability delegation methods.
     * 
     * @param capabilityDelegation The capability delegation methods list
     */
    public void setCapabilityDelegation(List<String> capabilityDelegation) {

        this.capabilityDelegation = capabilityDelegation != null ? new ArrayList<>(capabilityDelegation) : null;
    }

    /**
     * Get the services.
     * 
     * @return The services list
     */
    public List<Service> getService() {

        return service != null ? new ArrayList<>(service) : null;
    }

    /**
     * Set the services.
     * 
     * @param service The services list
     */
    public void setService(List<Service> service) {

        this.service = service != null ? new ArrayList<>(service) : null;
    }

    /**
     * Set the raw document.
     * 
     * @param rawDocument The raw document JSON string
     */
    public void setRawDocument(String rawDocument) {

        this.rawDocument = rawDocument;
    }

    /**
     * Get the raw document.
     * 
     * @return The raw document JSON string
     */
    public String getRawDocument() {

        return rawDocument;
    }

    /**
     * Get the raw map.
     * 
     * @return The raw document map
     */
    public Map<String, Object> getRawMap() {

        return rawMap != null ? new HashMap<>(rawMap) : null;
    }

    /**
     * Set the raw map.
     * 
     * @param rawMap The raw document map
     */
    public void setRawMap(Map<String, Object> rawMap) {

        this.rawMap = rawMap != null ? new HashMap<>(rawMap) : null;
    }

    /**
     * Find a verification method by its ID.
     *
     * @param methodId The verification method ID (can be full ID or fragment)
     * @return The verification method or null if not found
     */
    public VerificationMethod findVerificationMethod(String methodId) {

        if (verificationMethod == null || methodId == null) {
            return null;
        }

        // Try exact match first
        for (VerificationMethod method : verificationMethod) {
            if (methodId.equals(method.getId())) {
                return method;
            }
        }

        // Try fragment match
        String fragment = methodId.contains("#")
                ? methodId.substring(methodId.indexOf("#") + 1) : methodId;
        for (VerificationMethod method : verificationMethod) {
            if (method.getId() != null
                    && method.getId().endsWith("#" + fragment)) {
                return method;
            }
        }

        return null;
    }

    /**
     * Get the first verification method for assertion (signing).
     *
     * @return The first assertion method or null
     */
    public VerificationMethod getFirstAssertionMethod() {

        if (assertionMethod != null && !assertionMethod.isEmpty()) {
            String methodRef = assertionMethod.get(0);
            return findVerificationMethod(methodRef);
        }
        // Fall back to first verification method
        if (verificationMethod != null && !verificationMethod.isEmpty()) {
            return verificationMethod.get(0);
        }
        return null;
    }


    /**
     * Get string representation of the DID document.
     *
     * @return String representation
     */
    @Override
    public String toString() {

        int methodCount = verificationMethod != null ? verificationMethod.size() : 0;
        return "DIDDocument{"
                + "id='" + id + '\''
                + ", verificationMethodCount=" + methodCount
                + '}';
    }
}
