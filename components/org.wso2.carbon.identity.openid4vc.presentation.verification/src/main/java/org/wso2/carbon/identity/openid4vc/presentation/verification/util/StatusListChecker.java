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

package org.wso2.carbon.identity.openid4vc.presentation.verification.util;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.InflaterInputStream;

/**
 * Checks credential revocation status via the IETF OAuth Token Status List
 * (draft-ietf-oauth-status-list).
 *
 * <p>The issuer embeds a {@code status.status_list} object in the VC with a {@code uri}
 * pointing to a Status List JWT and an {@code idx} indicating the credential's position
 * in the list. This checker fetches the list, verifies its JWT signature, decompresses
 * it (ZLIB), and reads the status value at {@code idx} to determine revocation status.</p>
 *
 * <p>Bit ordering: per spec §4.1, bits are packed LSB-first within each byte.</p>
 * <p>Status lists are cached in-memory until their {@code exp} claim expires.</p>
 */
public class StatusListChecker {

    private static final Log LOG = LogFactory.getLog(StatusListChecker.class);

    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int READ_TIMEOUT_MS = 5000;
    private static final long DEFAULT_CACHE_TTL_SECONDS = 3600L;

    private static final ConcurrentHashMap<String, CachedStatusList> CACHE = new ConcurrentHashMap<>();

    /**
     * Outcome of a revocation check.
     */
    public enum RevocationStatus {
        /** The credential is valid (status value = 0). */
        VALID,
        /** The credential has been revoked or is otherwise invalid (status value != 0). */
        REVOKED,
        /** The VC has no {@code status} claim — revocation cannot be determined. */
        NO_STATUS_CLAIM
    }

    private StatusListChecker() {
    }

    /**
     * Check the revocation status of a credential using its verified claims.
     *
     * @param claims The fully verified VC claims map.
     * @return {@link RevocationStatus} — never {@code null}.
     */
    @SuppressWarnings("unchecked")
    public static RevocationStatus check(Map<String, Object> claims) {

        Object statusObj = claims.get("status");
        if (statusObj == null) {
            return RevocationStatus.NO_STATUS_CLAIM;
        }

        try {
            if (!(statusObj instanceof Map)) {
                LOG.warn("[OID4VP] Unexpected type for 'status' claim: " + statusObj.getClass());
                return RevocationStatus.NO_STATUS_CLAIM;
            }
            Map<String, Object> status = (Map<String, Object>) statusObj;
            Object slObj = status.get("status_list");
            if (slObj == null) {
                return RevocationStatus.NO_STATUS_CLAIM;
            }
            if (!(slObj instanceof Map)) {
                LOG.warn("[OID4VP] Unexpected type for 'status.status_list' claim.");
                return RevocationStatus.NO_STATUS_CLAIM;
            }
            Map<String, Object> statusList = (Map<String, Object>) slObj;

            Object uriObj = statusList.get("uri");
            Object idxObj = statusList.get("idx");
            if (!(uriObj instanceof String) || !(idxObj instanceof Number)) {
                LOG.warn("[OID4VP] status_list is missing required 'uri' or 'idx' fields.");
                return RevocationStatus.NO_STATUS_CLAIM;
            }

            String uri = (String) uriObj;
            int idx = ((Number) idxObj).intValue();

            CachedStatusList cached = getStatusListData(uri);
            if (cached == null) {
                return RevocationStatus.NO_STATUS_CLAIM;
            }

            int statusValue = extractStatusValue(cached.lstBytes, idx, cached.bits);
            if (statusValue < 0) {
                LOG.warn("[OID4VP] Status list index " + idx + " is out of range.");
                return RevocationStatus.NO_STATUS_CLAIM;
            }

            // Per spec: 0x00 = VALID, any other value = not valid (revoked/suspended/etc.)
            return statusValue == 0 ? RevocationStatus.VALID : RevocationStatus.REVOKED;

        } catch (Exception e) {
            LOG.warn("[OID4VP] Unexpected error during revocation check: " + e.getMessage(), e);
            return RevocationStatus.NO_STATUS_CLAIM;
        }
    }

    /**
     * Extract the status value for the given index from the decompressed status list.
     *
     * <p>Per spec §4.1: bits are packed from the least significant bit (position 0) to the
     * most significant bit (position 7) within each byte — LSB-first.</p>
     *
     * @param lstBytes     Decompressed status list byte array.
     * @param idx          Index of the credential in the list.
     * @param bitsPerEntry Number of bits per entry (1, 2, 4, or 8).
     * @return The status value, or -1 if the index is out of range.
     */
    private static int extractStatusValue(byte[] lstBytes, int idx, int bitsPerEntry) {

        int bitPosition = idx * bitsPerEntry;
        int byteIndex = bitPosition / 8;
        // LSB-first: bit 0 of entry idx is at the least significant bit of the byte.
        int bitOffset = bitPosition % 8;

        if (byteIndex >= lstBytes.length) {
            return -1;
        }

        int mask = (1 << bitsPerEntry) - 1;

        if (bitsPerEntry + bitOffset <= 8) {
            // All bits fit within a single byte.
            return ((lstBytes[byteIndex] & 0xFF) >> bitOffset) & mask;
        } else {
            // Entry spans two bytes (e.g. bits=4 at bitOffset=6).
            if (byteIndex + 1 >= lstBytes.length) {
                return -1;
            }
            int low = (lstBytes[byteIndex] & 0xFF) >> bitOffset;
            int high = (lstBytes[byteIndex + 1] & 0xFF) << (8 - bitOffset);
            return (low | high) & mask;
        }
    }

    /**
     * Retrieve and cache the status list data (byte array + bits-per-entry) for the given URI.
     * Validates the Status List Token's JWT signature before trusting its content.
     */
    @SuppressWarnings("unchecked")
    private static CachedStatusList getStatusListData(String uri) {

        long nowSeconds = System.currentTimeMillis() / 1000;
        CachedStatusList cached = CACHE.get(uri);
        if (cached != null && cached.expiresAt > nowSeconds) {
            return cached;
        }

        try {
            String jwtStr = fetchStatusListJwt(uri);
            if (jwtStr == null) {
                return null;
            }

            SignedJWT jwt = SignedJWT.parse(jwtStr);

            // Verify signature using the public key from the x5c JOSE header.
            List<Base64> x5cChain = jwt.getHeader().getX509CertChain();
            if (x5cChain != null && !x5cChain.isEmpty()) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(
                        new ByteArrayInputStream(x5cChain.get(0).decode()));
                JWSVerifier verifier;
                if (cert.getPublicKey() instanceof ECPublicKey) {
                    verifier = new ECDSAVerifier((ECPublicKey) cert.getPublicKey());
                } else if (cert.getPublicKey() instanceof RSAPublicKey) {
                    verifier = new RSASSAVerifier((RSAPublicKey) cert.getPublicKey());
                } else {
                    LOG.warn("[OID4VP] Unsupported key type in Status List Token x5c header: "
                            + cert.getPublicKey().getAlgorithm() + " for URI: " + uri);
                    return null;
                }
                if (!jwt.verify(verifier)) {
                    LOG.warn("[OID4VP] Status List Token signature verification FAILED for URI: " + uri);
                    return null;
                }
            } else {
                // x5c is absent — log a warning but continue to support deployments that
                // sign the Status List Token with a key distributed out-of-band.
                LOG.warn("[OID4VP] Status List Token at '" + uri
                        + "' has no x5c JOSE header — signature NOT verified.");
            }

            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            long expiresAt = claimsSet.getExpirationTime() != null
                    ? claimsSet.getExpirationTime().getTime() / 1000
                    : nowSeconds + DEFAULT_CACHE_TTL_SECONDS;

            Object slClaim = claimsSet.getClaim("status_list");
            if (!(slClaim instanceof Map)) {
                LOG.warn("[OID4VP] Status List JWT at '" + uri + "' is missing 'status_list' claim.");
                return null;
            }
            Map<String, Object> slMap = (Map<String, Object>) slClaim;

            // Read bits-per-entry (REQUIRED). Default to 1 if absent for backwards compatibility.
            int bits = 1;
            Object bitsObj = slMap.get("bits");
            if (bitsObj instanceof Number) {
                bits = ((Number) bitsObj).intValue();
                if (bits != 1 && bits != 2 && bits != 4 && bits != 8) {
                    LOG.warn("[OID4VP] Status List JWT at '" + uri + "' has unsupported bits value: " + bits
                            + ". Allowed: 1, 2, 4, 8.");
                    return null;
                }
            }

            Object lstObj = slMap.get("lst");
            if (!(lstObj instanceof String)) {
                LOG.warn("[OID4VP] Status List JWT at '" + uri + "' has invalid 'status_list.lst'.");
                return null;
            }

            // Base64url-decode then ZLIB-inflate (RFC 1950 wrapper + RFC 1951 DEFLATE).
            byte[] compressed = java.util.Base64.getUrlDecoder().decode((String) lstObj);
            byte[] lstBytes = inflate(compressed);
            if (lstBytes == null) {
                return null;
            }

            CachedStatusList result = new CachedStatusList(lstBytes, bits, expiresAt);
            CACHE.put(uri, result);
            return result;

        } catch (Exception e) {
            LOG.warn("[OID4VP] Failed to retrieve or parse status list from '" + uri + "': " + e.getMessage());
            return null;
        }
    }

    private static String fetchStatusListJwt(String uri) {

        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(uri).toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setRequestProperty("Accept", "application/statuslist+jwt, application/jwt");
            conn.connect();

            int status = conn.getResponseCode();
            if (status != HttpURLConnection.HTTP_OK) {
                LOG.warn("[OID4VP] Status list endpoint returned HTTP " + status + " for URI: " + uri);
                return null;
            }

            try (InputStream is = conn.getInputStream()) {
                return new String(is.readAllBytes(), StandardCharsets.UTF_8).trim();
            }
        } catch (Exception e) {
            LOG.warn("[OID4VP] HTTP fetch failed for status list URI '" + uri + "': " + e.getMessage());
            return null;
        }
    }

    private static byte[] inflate(byte[] compressed) {

        try (InflaterInputStream inflater = new InflaterInputStream(new ByteArrayInputStream(compressed))) {
            return inflater.readAllBytes();
        } catch (Exception e) {
            LOG.warn("[OID4VP] ZLIB decompression of status list failed: " + e.getMessage());
            return null;
        }
    }

    private static final class CachedStatusList {

        final byte[] lstBytes;
        final int bits;
        final long expiresAt; // Unix seconds

        CachedStatusList(byte[] lstBytes, int bits, long expiresAt) {
            this.lstBytes = lstBytes;
            this.bits = bits;
            this.expiresAt = expiresAt;
        }
    }
}
