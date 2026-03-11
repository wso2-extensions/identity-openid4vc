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

package org.wso2.carbon.identity.openid4vc.template.management.model;

import java.io.Serializable;
import java.util.Objects;

/**
 * Model representing a claim in a VC template.
 */
public class Claim implements Serializable {

    private static final long serialVersionUID = -6511692184196497538L;

    private String name;

    private String type;

    private String claimUri;

    public Claim() {

    }

    public Claim(String name, String type, String claimUri) {

        this.name = name;
        this.type = type;
        this.claimUri = claimUri;
    }

    public String getName() {

        return name;
    }

    public void setName(String name) {

        this.name = name;
    }

    public String getType() {

        return type;
    }

    public void setType(String type) {

        this.type = type;
    }

    public String getClaimUri() {

        return claimUri;
    }

    public void setClaimUri(String claimUri) {

        this.claimUri = claimUri;
    }

    @Override
    public boolean equals(Object o) {

        if (this == o) {
            return true;
        }
        if (!(o instanceof Claim)) {
            return false;
        }
        Claim claim = (Claim) o;
        return Objects.equals(name, claim.name)
                && Objects.equals(type, claim.type)
                && Objects.equals(claimUri, claim.claimUri);
    }

    @Override
    public int hashCode() {

        return Objects.hash(name, type, claimUri);
    }
}
