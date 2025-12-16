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

package org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.builders;

import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builder for creating W3C Verifiable Credential structures according to the W3C VC Data Model v2.
 * This builder specifically implements the W3C Verifiable Credentials Data Model specification.
 *
 * @see <a href="https://www.w3.org/TR/vc-data-model/">W3C Verifiable Credentials Data Model</a>
 */
public class W3CVCDataModelBuilder {

    private final List<String> contexts = new ArrayList<>();
    private final List<String> types = new ArrayList<>();
    private String id;
    private String issuer;
    private Instant validFrom;
    private Instant validUntil;
    private Map<String, String> credentialSubject;

    public W3CVCDataModelBuilder() {

        this.contexts.add(Constants.W3CVCDataModel.W3C_CREDENTIALS_V2_CONTEXT);
        this.types.add(Constants.W3CVCDataModel.VERIFIABLE_CREDENTIAL_TYPE);
    }

    /**
     * Set the credential ID. If not set, a random UUID will be generated.
     *
     * @param id the credential ID
     * @return this builder
     */
    public W3CVCDataModelBuilder id(String id) {

        this.id = id;
        return this;
    }

    /**
     * Add a context to the @context array.
     *
     * @param context the context URL or value
     * @return this builder
     */
    public W3CVCDataModelBuilder addContext(String context) {

        if (context != null && !context.isEmpty()) {
            this.contexts.add(context);
        }
        return this;
    }

    /**
     * Add a type to the type array.
     *
     * @param type the credential type
     * @return this builder
     */
    public W3CVCDataModelBuilder addType(String type) {

        if (type != null && !type.isEmpty()) {
            this.types.add(type);
        }
        return this;
    }

    /**
     * Set the issuer URL.
     *
     * @param issuer the issuer URL
     * @return this builder
     */
    public W3CVCDataModelBuilder issuer(String issuer) {

        this.issuer = issuer;
        return this;
    }

    /**
     * Set the validFrom instant.
     *
     * @param validFrom the validFrom instant
     * @return this builder
     */
    public W3CVCDataModelBuilder validFrom(Instant validFrom) {

        this.validFrom = validFrom;
        return this;
    }

    /**
     * Set the validUntil instant.
     *
     * @param validUntil the validUntil instant
     * @return this builder
     */
    public W3CVCDataModelBuilder validUntil(Instant validUntil) {

        this.validUntil = validUntil;
        return this;
    }

    /**
     * Set the credentialSubject claims.
     *
     * @param credentialSubject the subject claims map
     * @return this builder
     */
    public W3CVCDataModelBuilder credentialSubject(Map<String, String> credentialSubject) {

        this.credentialSubject = credentialSubject;
        return this;
    }

    /**
     * Build the W3C Verifiable Credential structure as a Map according to W3C VC Data Model v2.
     *
     * @return the W3C VC structure
     */
    public Map<String, Object> build() {

        Map<String, Object> vc = new LinkedHashMap<>();

        vc.put(Constants.W3CVCDataModel.CONTEXT, contexts);

        vc.put(Constants.W3CVCDataModel.ID, id);

        vc.put(Constants.W3CVCDataModel.TYPE, types);

        if (issuer != null) {
            vc.put(Constants.W3CVCDataModel.ISSUER, issuer);
        }
        if (validFrom != null) {
            vc.put(Constants.W3CVCDataModel.VALID_FROM, validFrom.toString());
        }
        if (validUntil != null) {
            vc.put(Constants.W3CVCDataModel.VALID_UNTIL, validUntil.toString());
        }
        if (credentialSubject != null && !credentialSubject.isEmpty()) {
            vc.put(Constants.W3CVCDataModel.CREDENTIAL_SUBJECT, credentialSubject);
        }
        return vc;
    }
}
