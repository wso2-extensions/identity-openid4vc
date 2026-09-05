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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.wso2.carbon.identity.openid4vc.presentation.did.exception.DIDServerException;
import org.wso2.carbon.identity.openid4vc.presentation.did.model.DIDDocument;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.DIDResolverService;
import org.wso2.carbon.identity.openid4vc.presentation.did.util.Constraints;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of DIDResolverService for resolving DIDs to DID Documents.
 * Supports did:web, did:jwk, and did:key methods.
 */
public class DIDResolverServiceImpl implements DIDResolverService {

    // Supported DID methods
    private static final String[] SUPPORTED_METHODS = { Constraints.METHOD_WEB };

    // Cache for resolved DID documents
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

    /**
     * Cache entry for DID documents.
     */
    private static class CacheEntry {

        final DIDDocument document;
        final long expiresAt;

        CacheEntry(DIDDocument document, long ttlMs) {

            this.document = document;
            this.expiresAt = System.currentTimeMillis() + ttlMs;
        }

        /**
         * Check if the cache entry is expired.
         * 
         * @return true if expired
         */
        boolean isExpired() {

            return System.currentTimeMillis() > expiresAt;
        }
    }

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    public DIDDocument resolve(String did) throws DIDServerException {

        return resolve(did, true);
    }

    @Override
    public DIDDocument resolve(String did, boolean useCache) throws DIDServerException {

        if (did == null || did.trim().isEmpty()) {
            throw DIDServerException.invalidFormat(did);
        }

        // Validate DID format
        if (!isValidDID(did)) {
            throw DIDServerException.invalidFormat(did);
        }

        // Check cache first
        if (useCache) {
            CacheEntry entry = cache.get(did);
            if (entry != null && !entry.isExpired()) {
                return entry.document;
            }
        }

        // Resolve based on method
        String method = getMethod(did);
        DIDDocument document;

        switch (method) {
            case Constraints.METHOD_WEB:
                document = resolveDidWeb(did);
                break;
            default:
                document = resolveViaUniversalResolver(did);
                break;
        }

        // Cache the result
        if (useCache) {
            cache.put(did, new CacheEntry(document, Constraints.DEFAULT_CACHE_TTL_MS));
        }

        return document;
    }

    @Override
    public PublicKey getPublicKey(String did, String keyId) throws DIDServerException {

        DIDDocument document = resolve(did);

        DIDDocument.VerificationMethod method;
        if (keyId != null && !keyId.isEmpty()) {
            method = document.findVerificationMethod(keyId);
        } else {
            method = document.getFirstAssertionMethod();
        }

        if (method == null) {
            throw DIDServerException.keyNotFound(did, keyId);
        }

        return extractPublicKey(method);
    }

    @Override
    public PublicKey getPublicKeyFromReference(String verificationMethodRef) throws DIDServerException {

        if (verificationMethodRef == null || verificationMethodRef.isEmpty()) {
            throw new DIDServerException("Verification method reference is null or empty");
        }

        String did;
        String keyId = null;

        if (verificationMethodRef.contains("#")) {
            String[] parts = verificationMethodRef.split("#", 2);
            did = parts[0];
            keyId = parts[1];
        } else {
            did = verificationMethodRef;
        }

        return getPublicKey(did, keyId);
    }

    @Override
    public boolean isSupported(String did) {

        return isValidDID(did);
    }

    @Override
    public String getMethod(String did) {

        if (did == null || !did.startsWith("did:")) {
            return null;
        }
        String[] parts = did.split(":");
        return parts.length >= 2 ? parts[1] : null;
    }

    @Override
    public String[] getSupportedMethods() {

        return SUPPORTED_METHODS.clone();
    }

    @Override
    public void clearCache(String did) {

        cache.remove(did);
    }

    @Override
    public void clearAllCache() {

        cache.clear();
    }

    @Override
    public boolean isValidDID(String did) {

        if (did == null || did.isEmpty()) {
            return false;
        }
        // Basic DID format: did:method:identifier
        String[] parts = did.split(":");
        return parts.length >= 3 && "did".equals(parts[0]) && !parts[1].isEmpty() && !parts[2].isEmpty();
    }

    @Override
    public String getIdentifier(String did) {

        if (!isValidDID(did)) {
            return null;
        }
        // Return everything after "did:method:"
        int methodEndIndex = did.indexOf(':', 4); // Skip "did:"
        if (methodEndIndex > 0 && methodEndIndex < did.length() - 1) {
            return did.substring(methodEndIndex + 1);
        }
        return null;
    }

    // Resolution methods for different DID types

    /**
     * Resolve a did:web DID.
     * did:web:example.com → https://example.com/.well-known/did.json
     * did:web:example.com:path:to:did → https://example.com/path/to/did/did.json
     * 
     * @param did The DID to resolve.
     * @return Resolved DID document.
     * @throws DIDServerException If resolution fails.
     */
    private DIDDocument resolveDidWeb(String did) throws DIDServerException {

        try {
            String identifier = getIdentifier(did);
            if (identifier == null) {
                throw DIDServerException.invalidFormat(did);
            }

            // Convert to URL
            // Replace : with / for path segments
            String path = identifier.replace(":", "/");
            // URL decode %3A back to : for port numbers
            path = path.replace("%3A", ":");

            String url;
            if (path.contains("/")) {
                // Path-based: https://domain/path/did.json
                url = "https://" + path + "/did.json";
            } else {
                // Domain-only: https://domain/.well-known/did.json
                url = "https://" + path + "/.well-known/did.json";
            }

            // Fetch the DID document
            String jsonResponse = fetchUrl(url);
            return parseDIDDocument(did, jsonResponse);

        } catch (DIDServerException e) {
            throw e;
        } catch (IOException e) {
            throw DIDServerException.networkError(did, e);
        }
    }

    /**
     * Resolve a DID via DIF Universal Resolver as a catch-all fallback.
     *
     * @param did The DID to resolve.
     * @return Resolved DID document.
    * @throws DIDServerException If resolution fails.
     */
    private DIDDocument resolveViaUniversalResolver(String did) throws DIDServerException {

        try {
            String url = Constraints.UNIVERSAL_RESOLVER_URL + did;
            String jsonResponse = fetchUrl(url);

            JsonObject responseJson = JsonParser.parseString(jsonResponse).getAsJsonObject();
            JsonElement didDocumentElement = responseJson.get("didDocument");

            if (didDocumentElement == null || didDocumentElement.isJsonNull() || !didDocumentElement.isJsonObject()) {
                throw DIDServerException.invalidDocument(did,
                        "Universal Resolver response does not contain a valid didDocument");
            }

            JsonObject didDocumentJson = didDocumentElement.getAsJsonObject();
            return parseDIDDocument(did, didDocumentJson.toString());

        } catch (DIDServerException e) {
            throw e;
        } catch (IOException e) {
            throw DIDServerException.networkError(did, e);
        } catch (JsonParseException | IllegalStateException e) {
            throw DIDServerException.invalidDocument(did,
                    "Invalid Universal Resolver response: " + e.getMessage());
        }
    }

    /**
     * Parse a DID document from JSON.
     * 
     * @param did The DID identifier.
     * @param jsonString The JSON string of the DID document.
     * @return Parsed DIDDocument object.
     * @throws DIDServerException If parsing fails.
     */
    protected DIDDocument parseDIDDocument(String did, String jsonString) throws DIDServerException {

        try {
            JsonObject json = JsonParser.parseString(jsonString).getAsJsonObject();

            DIDDocument document = new DIDDocument();
            document.setRawDocument(jsonString);

            // Parse id
            if (json.has("id")) {
                document.setId(json.get("id").getAsString());
            } else {
                document.setId(did);
            }

            // Parse @context
            if (json.has("@context")) {
                JsonElement context = json.get("@context");
                List<String> contexts = new ArrayList<>();
                if (context.isJsonArray()) {
                    for (JsonElement el : context.getAsJsonArray()) {
                        if (el.isJsonPrimitive()) {
                            contexts.add(el.getAsString());
                        }
                    }
                } else if (context.isJsonPrimitive()) {
                    contexts.add(context.getAsString());
                }
                document.setContext(contexts);
            }

            // Parse controller
            if (json.has("controller")) {
                document.setController(json.get("controller").getAsString());
            }

            // Parse verification methods
            if (json.has("verificationMethod")) {
                JsonArray methods = json.getAsJsonArray("verificationMethod");
                for (JsonElement el : methods) {
                    if (el.isJsonObject()) {
                        document.addVerificationMethod(parseVerificationMethod(el.getAsJsonObject()));
                    }
                }
            }

            // Parse authentication
            document.setAuthentication(parseVerificationRelationship(json, "authentication"));
            document.setAssertionMethod(parseVerificationRelationship(json, "assertionMethod"));
            document.setKeyAgreement(parseVerificationRelationship(json, "keyAgreement"));

            // Parse services
            if (json.has("service")) {
                JsonArray services = json.getAsJsonArray("service");
                List<DIDDocument.Service> serviceList = new ArrayList<>();
                for (JsonElement el : services) {
                    if (el.isJsonObject()) {
                        serviceList.add(parseService(el.getAsJsonObject()));
                    }
                }
                document.setService(serviceList);
            }

            return document;

        } catch (JsonParseException | ClassCastException e) {
            throw DIDServerException.invalidDocument(did, e.getMessage());
        }
    }

    /**
     * Parse a verification method from JSON.
     * 
     * @param json The JSON object representing the verification method.
     * @return Parsed VerificationMethod object.
     */
    private DIDDocument.VerificationMethod parseVerificationMethod(JsonObject json) {

        DIDDocument.VerificationMethod method = new DIDDocument.VerificationMethod();

        if (json.has("id")) {
            method.setId(json.get("id").getAsString());
        }
        if (json.has("type")) {
            method.setType(json.get("type").getAsString());
        }
        if (json.has("controller")) {
            method.setController(json.get("controller").getAsString());
        }
        if (json.has("publicKeyJwk")) {
            JsonObject jwk = json.getAsJsonObject("publicKeyJwk");
            method.setPublicKeyJwk(jwk.toString());

            Map<String, Object> jwkMap = new HashMap<>();
            for (String key : jwk.keySet()) {
                JsonElement value = jwk.get(key);
                if (value.isJsonPrimitive()) {
                    jwkMap.put(key, value.getAsString());
                }
            }
            method.setPublicKeyJwkMap(jwkMap);
        }
        if (json.has("publicKeyMultibase")) {
            method.setPublicKeyMultibase(json.get("publicKeyMultibase").getAsString());
        }
        if (json.has("publicKeyBase58")) {
            method.setPublicKeyBase58(json.get("publicKeyBase58").getAsString());
        }
        if (json.has("publicKeyPem")) {
            method.setPublicKeyPem(json.get("publicKeyPem").getAsString());
        }

        return method;
    }

    /**
     * Parse a verification relationship (authentication, assertionMethod, etc.).
     * 
     * @param json The JSON object of the DID document.
     * @param propertyName The property name of the relationship.
     * @return List of verification method references.
     */
    private List<String> parseVerificationRelationship(JsonObject json, String propertyName) {

        List<String> result = new ArrayList<>();
        if (json.has(propertyName)) {
            JsonElement el = json.get(propertyName);
            if (el.isJsonArray()) {
                for (JsonElement item : el.getAsJsonArray()) {
                    if (item.isJsonPrimitive()) {
                        result.add(item.getAsString());
                    } else if (item.isJsonObject() && item.getAsJsonObject().has("id")) {
                        result.add(item.getAsJsonObject().get("id").getAsString());
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse a service from JSON.
     * 
     * @param json The JSON object of the service.
     * @return Parsed Service object.
     */
    private DIDDocument.Service parseService(JsonObject json) {

        DIDDocument.Service service = new DIDDocument.Service();

        if (json.has("id")) {
            service.setId(json.get("id").getAsString());
        }
        if (json.has("type")) {
            service.setType(json.get("type").getAsString());
        }
        if (json.has("serviceEndpoint")) {
            JsonElement endpoint = json.get("serviceEndpoint");
            if (endpoint.isJsonPrimitive()) {
                service.setServiceEndpoint(endpoint.getAsString());
            } else if (endpoint.isJsonObject()) {
                Map<String, Object> endpointMap = new HashMap<>();
                for (String key : endpoint.getAsJsonObject().keySet()) {
                    endpointMap.put(key, endpoint.getAsJsonObject().get(key).getAsString());
                }
                service.setServiceEndpointMap(endpointMap);
            }
        }

        return service;
    }

    /**
     * Extract a public key from a verification method.
     * 
     * @param method The verification method.
     * @return The extracted PublicKey object.
     * @throws DIDServerException If extraction fails.
     */
    private PublicKey extractPublicKey(DIDDocument.VerificationMethod method) throws DIDServerException {

        try {
            // Try JWK first
            if (method.getPublicKeyJwkMap() != null) {
                return jwkToPublicKey(method.getPublicKeyJwkMap());
            }

            // Try multibase
            if (method.getPublicKeyMultibase() != null) {
                return multibaseToPublicKey(method.getPublicKeyMultibase(), method.getType());
            }

            // Try base58
            if (method.getPublicKeyBase58() != null) {
                return base58ToPublicKey(method.getPublicKeyBase58(), method.getType());
            }

            throw new DIDServerException("No public key material found in verification method");

        } catch (DIDServerException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new DIDServerException("Failed to extract public key: " + e.getMessage(), e);
        }
    }

    /**
     * Convert a JWK to a PublicKey.
     * 
     * @param jwk The JWK map.
     * @return The PublicKey object.
     * @throws GeneralSecurityException If security operation fails.
     * @throws DIDServerException If conversion fails.
     */
    private PublicKey jwkToPublicKey(Map<String, Object> jwk) throws GeneralSecurityException, DIDServerException {

        String kty = (String) jwk.get("kty");

        if ("RSA".equals(kty)) {
            return jwkToRsaPublicKey(jwk);
        } else if ("EC".equals(kty)) {
            return jwkToEcPublicKey(jwk);
        } else if ("OKP".equals(kty)) {
            return jwkToOkpPublicKey(jwk);
        }

        throw new DIDServerException("Unsupported JWK key type: " + kty);
    }

    /**
     * Convert RSA JWK to PublicKey.
     * 
     * @param jwk The JWK map.
     * @return The RSA PublicKey object.
     * @throws GeneralSecurityException If security operation fails.
     */
    private PublicKey jwkToRsaPublicKey(Map<String, Object> jwk) throws GeneralSecurityException {

        String n = (String) jwk.get("n");
        String e = (String) jwk.get("e");

        BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(n));
        BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(e));

        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

    /**
     * Convert EC JWK to PublicKey.
     * 
     * @param jwk The JWK map.
     * @return The EC PublicKey object.
     * @throws GeneralSecurityException If security operation fails.
     * @throws DIDServerException If conversion fails.
     */
    private PublicKey jwkToEcPublicKey(Map<String, Object> jwk) throws GeneralSecurityException,
            DIDServerException {

        String crv = (String) jwk.get("crv");
        String x = (String) jwk.get("x");
        String y = (String) jwk.get("y");

        BigInteger xCoord = new BigInteger(1, Base64.getUrlDecoder().decode(x));
        BigInteger yCoord = new BigInteger(1, Base64.getUrlDecoder().decode(y));

        ECPoint point = new ECPoint(xCoord, yCoord);
        ECParameterSpec params = getECParameterSpec(crv);

        ECPublicKeySpec spec = new ECPublicKeySpec(point, params);
        KeyFactory factory = KeyFactory.getInstance("EC");
        return factory.generatePublic(spec);
    }

    /**
     * Convert OKP (Ed25519) JWK to PublicKey.
     * 
     * @param jwk The JWK map.
     * @return The PublicKey object.
     * @throws GeneralSecurityException If security operation fails.
     * @throws DIDServerException If conversion fails.
     */
    private PublicKey jwkToOkpPublicKey(Map<String, Object> jwk) throws GeneralSecurityException,
            DIDServerException {

        String crv = (String) jwk.get("crv");
        String x = (String) jwk.get("x");

        if (!"Ed25519".equals(crv)) {
            throw new DIDServerException("Unsupported OKP curve: " + crv);
        }

        byte[] keyBytes = new Base64URL(x).decode();
        return bytesToEd25519PublicKey(keyBytes);
    }

    /**
     * Convert multibase encoded key to PublicKey.
     * 
     * @param multibase The multibase encoded key string.
     * @param keyType The key type (e.g., "Ed25519VerificationKey2020").
     * @return The PublicKey object.
     * @throws GeneralSecurityException If security operation fails.
     * @throws DIDServerException If conversion fails.
     */
    private PublicKey multibaseToPublicKey(String multibase, String keyType) throws GeneralSecurityException,
            DIDServerException {

        if (multibase.startsWith("z")) {
            // Base58btc
            byte[] decoded = base58Decode(multibase.substring(1));
            if (decoded.length > 2) {
                byte[] keyBytes = Arrays.copyOfRange(decoded, 2, decoded.length);
                return bytesToPublicKey(keyBytes, keyType);
            }
        }
        throw new DIDServerException("Unsupported multibase encoding: " + multibase);
    }

    /**
     * Convert base58 encoded key to PublicKey.
     * 
     * @param base58 The base58 encoded key string.
     * @param keyType The key type.
     * @return The PublicKey object.
     * @throws GeneralSecurityException If security operation fails.
     * @throws DIDServerException If conversion fails.
     */
    private PublicKey base58ToPublicKey(String base58, String keyType) throws GeneralSecurityException,
            DIDServerException {

        byte[] keyBytes = base58Decode(base58);
        if (keyBytes.length == 0) {
            throw new DIDServerException("Failed to decode base58 key");
        }
        return bytesToPublicKey(keyBytes, keyType);
    }

    /**
     * Convert raw key bytes to PublicKey based on key type.
     * 
     * @param keyBytes The raw key bytes.
     * @param keyType The key type.
     * @return The PublicKey object.
     * @throws GeneralSecurityException If security operation fails.
     * @throws DIDServerException If conversion fails.
     */
    private PublicKey bytesToPublicKey(byte[] keyBytes, String keyType) throws GeneralSecurityException,
            DIDServerException {

        if (keyType != null && keyType.contains("Ed25519")) {
            // Ed25519 key
            return bytesToEd25519PublicKey(keyBytes);
        }
        throw new DIDServerException("Unsupported key type for byte conversion: " + keyType);
    }

    /**
     * Convert raw bytes to Ed25519 PublicKey.
     * 
     * @param keyBytes The raw key bytes.
     * @return Ed25519 PublicKey object.
     * @throws GeneralSecurityException If security operation fails.
     */
    private PublicKey bytesToEd25519PublicKey(byte[] keyBytes) throws GeneralSecurityException {

        // Construct SubjectPublicKeyInfo for Ed25519 X.509
        // Sequence of (AlgorithmIdentifier, BitString(keyBytes))
        // 30 2A 30 05 06 03 2B 65 70 03 21 00 <32 bytes>
        byte[] encoded = new byte[44];
        encoded[0] = 0x30; encoded[1] = 0x2A;
        encoded[2] = 0x30; encoded[3] = 0x05;
        encoded[4] = 0x06; encoded[5] = 0x03;
        encoded[6] = 0x2B; encoded[7] = 0x65; encoded[8] = 0x70;
        encoded[9] = 0x03; encoded[10] = 0x21; encoded[11] = 0x00;
        System.arraycopy(keyBytes, 0, encoded, 12, 32);

        java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", "BC");
        return keyFactory.generatePublic(spec);
    }

    /**
     * Get EC parameter spec for a curve name.
     * 
     * @param curveName The name of the EC curve.
     * @return The ECParameterSpec object.
     * @throws GeneralSecurityException If security operation fails.
     * @throws DIDServerException If curve is unsupported.
     */
    private ECParameterSpec getECParameterSpec(String curveName) throws GeneralSecurityException,
            DIDServerException {

        // Get the EC parameter spec for standard curves
        java.security.AlgorithmParameters parameters = java.security.AlgorithmParameters.getInstance("EC");

        String stdName;
        switch (curveName) {
            case "P-256":
                stdName = "secp256r1";
                break;
            case "P-384":
                stdName = "secp384r1";
                break;
            case "P-521":
                stdName = "secp521r1";
                break;
            case "secp256k1":
                stdName = "secp256k1";
                break;
            default:
                throw new DIDServerException("Unsupported EC curve: " + curveName);
        }

        parameters.init(new java.security.spec.ECGenParameterSpec(stdName));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }

    /**
     * Fetch content from a URL.
     * 
     * @param urlString The URL to fetch.
     * @return The response content string.
     * @throws IOException If network operation fails.
     * @throws DIDServerException If URL is invalid or response is error.
     */
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value = "URLCONNECTION_SSRF_FD",
            justification = "URL is validated to use the HTTPS scheme only and is constructed "
                    + "from a parsed DID identifier, not from arbitrary user-supplied input.")
    protected String fetchUrl(String urlString) throws IOException, DIDServerException {

        if (urlString == null || !urlString.startsWith("https://")) {
            throw new DIDServerException("Only HTTPS URLs are permitted for DID document fetching: " + urlString);
        }
        URL url = java.net.URI.create(urlString).toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        try {
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(Constraints.CONNECTION_TIMEOUT_MS);
            conn.setReadTimeout(Constraints.READ_TIMEOUT_MS);
            conn.setRequestProperty("Accept", "application/json");

            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                throw new DIDServerException(
                        "HTTP error fetching DID document: " + responseCode);
            }

            StringBuilder response = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
            }

            return response.toString();

        } finally {
            conn.disconnect();
        }
    }

    /**
     * Decode base58 string.
     * 
     * @param base58 The base58 encoded string.
     * @return The decoded byte array.
     */
    private byte[] base58Decode(String base58) {

        // Base58 alphabet (Bitcoin)
        String alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        if (base58 == null || base58.isEmpty()) {
            return new byte[0];
        }

        // Count leading zeros
        int zeros = 0;
        for (int i = 0; i < base58.length() && base58.charAt(i) == '1'; i++) {
            zeros++;
        }

        // Decode
        BigInteger value = BigInteger.ZERO;
        BigInteger base = BigInteger.valueOf(58);

        for (int i = 0; i < base58.length(); i++) {
            int index = alphabet.indexOf(base58.charAt(i));
            if (index < 0) {
                return new byte[0];
            }
            value = value.multiply(base).add(BigInteger.valueOf(index));
        }

        byte[] decoded = value.toByteArray();

        // Remove leading zero if present (sign byte)
        if (decoded.length > 0 && decoded[0] == 0) {
            decoded = Arrays.copyOfRange(decoded, 1, decoded.length);
        }

        // Add leading zeros back
        if (zeros > 0) {
            byte[] result = new byte[zeros + decoded.length];
            System.arraycopy(decoded, 0, result, zeros, decoded.length);
            return result;
        }

        return decoded;
    }

    /**
     * Reverse byte array (for Ed25519 little-endian format).
     */
    /**
     * Reverse byte array (for Ed25519 little-endian format).
     * 
     * @deprecated Not used with Nimbus OctetKeyPair implementation
     */

    /**
     * Generate an Ed25519 key pair using Bouncy Castle for DID operations.
     * 
     * @return The generated OctetKeyPair.
     * @throws Exception If key generation fails.
     */
    public static OctetKeyPair generateEd25519KeyPair() throws Exception {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "BC");
        KeyPair kp = kpg.generateKeyPair();

        byte[] publicKeyBytes = kp.getPublic().getEncoded();
        byte[] privateKeyBytes = kp.getPrivate().getEncoded();

        OctetKeyPair okp = new OctetKeyPair.Builder(
                Curve.Ed25519,
                Base64URL.encode(publicKeyBytes))
                .d(Base64URL.encode(privateKeyBytes))
                .build();

        return okp;
    }
}
