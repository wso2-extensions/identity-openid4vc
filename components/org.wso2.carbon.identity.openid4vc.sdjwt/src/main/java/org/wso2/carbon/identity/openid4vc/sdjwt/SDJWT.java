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

package org.wso2.carbon.identity.openid4vc.sdjwt;

import org.wso2.carbon.identity.openid4vc.sdjwt.constant.SDJWTConstants;
import org.wso2.carbon.identity.openid4vc.sdjwt.exception.SDJWTException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Represents an SD-JWT consisting of:
 * <ul>
 *   <li>A Credential JWT (issuer-signed)</li>
 *   <li>Zero or more Disclosures</li>
 *   <li>An optional Key Binding JWT</li>
 * </ul>
 * <p>
 * The serialized format is:
 * {@code <Credential-JWT>~<Disclosure 1>~...~<Disclosure N>~[<Key-Binding-JWT>]}
 * <p>
 * If no Key Binding JWT is present, the string ends with a tilde (~).
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/">SD-JWT Specification</a>
 */
public class SDJWT {

    private final String credentialJwt;
    private final List<Disclosure> disclosures;
    private final String bindingJwt;

    /**
     * Create an SD-JWT without a Key Binding JWT.
     *
     * @param credentialJwt The issuer-signed credential JWT
     * @param disclosures   The disclosures to include
     */
    public SDJWT(String credentialJwt, Collection<Disclosure> disclosures) {

        this(credentialJwt, disclosures, null);
    }

    /**
     * Create an SD-JWT with an optional Key Binding JWT.
     *
     * @param credentialJwt The issuer-signed credential JWT
     * @param disclosures   The disclosures to include
     * @param bindingJwt    The optional Key Binding JWT (can be null)
     */
    public SDJWT(String credentialJwt, Collection<Disclosure> disclosures, String bindingJwt) {

        if (credentialJwt == null || credentialJwt.isEmpty()) {
            throw new IllegalArgumentException("Credential JWT cannot be null or empty");
        }
        this.credentialJwt = credentialJwt;
        this.disclosures = disclosures != null ? new ArrayList<>(disclosures) : new ArrayList<>();
        this.bindingJwt = bindingJwt;
    }

    /**
     * Serialize the SD-JWT to its string representation.
     * <p>
     * Format without Key Binding: {@code JWT~disc1~disc2~...~discN~}
     * Format with Key Binding: {@code JWT~disc1~disc2~...~discN~KB-JWT}
     *
     * @return The serialized SD-JWT string
     */
    public String serialize() {

        StringBuilder sb = new StringBuilder();
        sb.append(credentialJwt);

        for (Disclosure disclosure : disclosures) {
            sb.append(SDJWTConstants.DISCLOSURE_SEPARATOR);
            sb.append(disclosure.getDisclosure());
        }

        sb.append(SDJWTConstants.DISCLOSURE_SEPARATOR);

        if (bindingJwt != null && !bindingJwt.isEmpty()) {
            sb.append(bindingJwt);
        }

        return sb.toString();
    }

    /**
     * Parse an SD-JWT string into an SDJWT object.
     * <p>
     * Note: This method parses the structure but does not validate signatures.
     *
     * @param sdJwtString The serialized SD-JWT string
     * @return Parsed SDJWT object
     * @throws SDJWTException If parsing fails
     */
    public static SDJWT parse(String sdJwtString) throws SDJWTException {

        if (sdJwtString == null || sdJwtString.isEmpty()) {
            throw new SDJWTException("SD-JWT string cannot be null or empty");
        }

        // Split by tilde, keeping empty strings at the end
        String[] parts = sdJwtString.split(Pattern.quote(SDJWTConstants.DISCLOSURE_SEPARATOR), -1);

        if (parts.length < 2) {
            throw new SDJWTException("Invalid SD-JWT format: must contain at least JWT and trailing separator");
        }

        // First part is always the credential JWT
        String jwt = parts[0];
        if (jwt.isEmpty()) {
            throw new SDJWTException("Invalid SD-JWT: credential JWT is empty");
        }

        // Parse disclosures (all middle parts)
        List<Disclosure> parsedDisclosures = new ArrayList<>();
        for (int i = 1; i < parts.length - 1; i++) {
            if (!parts[i].isEmpty()) {
                parsedDisclosures.add(Disclosure.parse(parts[i]));
            }
        }

        // Last part is either empty (no binding JWT) or the binding JWT
        String lastPart = parts[parts.length - 1];
        String bindingJwtParsed = null;
        if (!lastPart.isEmpty()) {
            bindingJwtParsed = lastPart;
        }

        return new SDJWT(jwt, parsedDisclosures, bindingJwtParsed);
    }

    /**
     * Check if this SD-JWT has a Key Binding JWT.
     *
     * @return true if a Key Binding JWT is present
     */
    public boolean hasKeyBinding() {

        return bindingJwt != null && !bindingJwt.isEmpty();
    }

    /**
     * Get the credential JWT (the issuer-signed part).
     *
     * @return The credential JWT string
     */
    public String getCredentialJwt() {

        return credentialJwt;
    }

    /**
     * Get the list of disclosures.
     *
     * @return List of Disclosure objects
     */
    public List<Disclosure> getDisclosures() {

        return new ArrayList<>(disclosures);
    }

    /**
     * Get the number of disclosures.
     *
     * @return Number of disclosures
     */
    public int getDisclosureCount() {

        return disclosures.size();
    }

    /**
     * Get the Key Binding JWT.
     *
     * @return The Key Binding JWT string, or null if not present
     */
    public String getBindingJwt() {

        return bindingJwt;
    }

    @Override
    public String toString() {

        return serialize();
    }
}
