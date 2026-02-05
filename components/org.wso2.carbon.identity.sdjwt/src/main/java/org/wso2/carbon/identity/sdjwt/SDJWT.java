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

package org.wso2.carbon.identity.sdjwt;

import org.wso2.carbon.identity.sdjwt.constant.SDJWTConstants;
import org.wso2.carbon.identity.sdjwt.exception.SDJWTException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Represents an SD-JWT consisting of:
 * <ul>
 *   <li>An Issuer-signed JWT</li>
 *   <li>Zero or more Disclosures</li>
 *   <li>An optional Key Binding JWT</li>
 * </ul>
 * <p>
 * The serialized format is:
 * {@code <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~[<Key Binding JWT>]}
 * <p>
 * If no Key Binding JWT is present, the string ends with a tilde (~).
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9901.html">RFC 9901 - SD-JWT Specification</a>
 */
public class SDJWT {

    private final String issuerSignedJwt;
    private final List<Disclosure> disclosures;
    private final String keyBindingJwt;

    /**
     * Create an SD-JWT without a Key Binding JWT.
     *
     * @param issuerSignedJwt The Issuer-signed JWT
     * @param disclosures     The disclosures to include
     */
    public SDJWT(String issuerSignedJwt, Collection<Disclosure> disclosures) {

        this(issuerSignedJwt, disclosures, null);
    }

    /**
     * Create an SD-JWT with an optional Key Binding JWT.
     *
     * @param issuerSignedJwt The Issuer-signed JWT
     * @param disclosures     The disclosures to include
     * @param keyBindingJwt   The optional Key Binding JWT (can be null)
     */
    public SDJWT(String issuerSignedJwt, Collection<Disclosure> disclosures, String keyBindingJwt) {

        if (issuerSignedJwt == null || issuerSignedJwt.isEmpty()) {
            throw new IllegalArgumentException("Issuer-signed JWT cannot be null or empty");
        }
        this.issuerSignedJwt = issuerSignedJwt;
        this.disclosures = disclosures != null ? new ArrayList<>(disclosures) : new ArrayList<>();
        this.keyBindingJwt = keyBindingJwt;
    }

    /**
     * Serialize the SD-JWT to its string representation.
     * <p>
     * Format without Key Binding: {@code <Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~}
     * Format with Key Binding:
     *  {@code <Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~<Key Binding JWT>}
     *
     * @return The serialized SD-JWT string
     */
    public String serialize() {

        StringBuilder sb = new StringBuilder();
        sb.append(issuerSignedJwt);

        for (Disclosure disclosure : disclosures) {
            sb.append(SDJWTConstants.DISCLOSURE_SEPARATOR);
            sb.append(disclosure.getDisclosure());
        }

        sb.append(SDJWTConstants.DISCLOSURE_SEPARATOR);

        if (keyBindingJwt != null && !keyBindingJwt.isEmpty()) {
            sb.append(keyBindingJwt);
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

        // First part is always the Issuer-signed JWT
        String jwt = parts[0];
        if (jwt.isEmpty()) {
            throw new SDJWTException("Invalid SD-JWT: Issuer-signed JWT is empty");
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

        return keyBindingJwt != null && !keyBindingJwt.isEmpty();
    }

    /**
     * Get the Issuer-signed JWT.
     *
     * @return The Issuer-signed JWT string
     */
    public String getIssuerSignedJwt() {

        return issuerSignedJwt;
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
    public String getKeyBindingJwt() {

        return keyBindingJwt;
    }

    @Override
    public String toString() {

        return serialize();
    }
}
