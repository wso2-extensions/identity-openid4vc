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

package org.wso2.carbon.identity.openid4vc.template.management.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Model representing a VC template.
 */
public class VCTemplate {

    private String id;

    private String identifier;

    private String displayName;

    private String description;

    private String format;

    private String signingAlgorithm;

    private List<String> claims = new ArrayList<>();

    private Integer expiresIn;

    private String offerId;

    private Integer cursorKey;

    public String getId() {

        return id;
    }

    public void setId(String id) {

        this.id = id;
    }

    public String getIdentifier() {

        return identifier;
    }

    public void setIdentifier(String identifier) {

        this.identifier = identifier;
    }

    public String getFormat() {

        return format;
    }

    public void setFormat(String format) {

        this.format = format;
    }

    public String getSigningAlgorithm() {

        return signingAlgorithm;
    }

    public void setSigningAlgorithm(String signingAlgorithm) {

        this.signingAlgorithm = signingAlgorithm;
    }

    public List<String> getClaims() {

        return claims;
    }

    public void setClaims(List<String> claims) {

        this.claims = claims;
    }

    public String getDisplayName() {

        return displayName;
    }

    public void setDisplayName(String displayName) {

        this.displayName = displayName;
    }

    public String getDescription() {

        return description;
    }

    public void setDescription(String description) {

        this.description = description;
    }

    public Integer getExpiresIn() {

        return expiresIn;
    }

    public void setExpiresIn(Integer expiresIn) {

        this.expiresIn = expiresIn;
    }


    public String getOfferId() {

        return offerId;
    }

    public void setOfferId(String offerId) {

        this.offerId = offerId;
    }

    public Integer getCursorKey() {

        return cursorKey;
    }

    public void setCursorKey(Integer cursorKey) {

        this.cursorKey = cursorKey;
    }
}
