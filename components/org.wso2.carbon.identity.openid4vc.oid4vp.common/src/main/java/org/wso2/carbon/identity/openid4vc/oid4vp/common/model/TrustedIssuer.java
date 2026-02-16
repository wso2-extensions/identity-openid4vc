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

package org.wso2.carbon.identity.openid4vc.oid4vp.common.model;

/**
 * Model class representing a trusted credential issuer.
 * Stores metadata about which issuers are trusted to issue credentials
 * that can be presented to this verifier.
 */
public class TrustedIssuer {

    private String issuerDid;
    private String tenantDomain;
    private int tenantId;
    private String addedBy;
    private long addedTimestamp;
    private String description;
    private boolean active;

    /**
     * Default constructor.
     */
    public TrustedIssuer() {
        this.active = true;
    }

    /**
     * Constructor with required fields.
     * 
     * @param issuerDid DID of the trusted issuer
     * @param tenantDomain Tenant domain
     * @param addedBy User who added this trust
     */
    public TrustedIssuer(String issuerDid, String tenantDomain, String addedBy) {
        this.issuerDid = issuerDid;
        this.tenantDomain = tenantDomain;
        this.addedBy = addedBy;
        this.addedTimestamp = System.currentTimeMillis();
        this.active = true;
    }

    // Getters and setters

    public String getIssuerDid() {
        return issuerDid;
    }

    public void setIssuerDid(String issuerDid) {
        this.issuerDid = issuerDid;
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    public int getTenantId() {
        return tenantId;
    }

    public void setTenantId(int tenantId) {
        this.tenantId = tenantId;
    }

    public String getAddedBy() {
        return addedBy;
    }

    public void setAddedBy(String addedBy) {
        this.addedBy = addedBy;
    }

    public long getAddedTimestamp() {
        return addedTimestamp;
    }

    public void setAddedTimestamp(long addedTimestamp) {
        this.addedTimestamp = addedTimestamp;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    @Override
    public String toString() {
        return "TrustedIssuer{" +
                "issuerDid='" + issuerDid + '\'' +
                ", tenantDomain='" + tenantDomain + '\'' +
                ", addedBy='" + addedBy + '\'' +
                ", addedTimestamp=" + addedTimestamp +
                ", active=" + active +
                '}';
    }
}
