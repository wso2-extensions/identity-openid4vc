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

package org.wso2.carbon.identity.openid4vc.presentation.util;

import org.apache.commons.logging.Log;

/**
 * Utility class for structured OpenID4VP logging.
 * Provides consistent logging format matching server.js implementation.
 */
public class OpenID4VPLogger {

    // DID Resolution Logging

    public static void logDIDResolutionStart(Log log, String did) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("[DID Resolution] Resolving DID: %s", did));
        }
    }

    public static void logDIDResolutionURL(Log log, String did, String url) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("[DID Resolution] Fetching DID document from: %s", url));
        }
    }

    public static void logDIDResolutionSuccess(Log log, String did) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("[DID Resolution] ✓ Successfully resolved DID document"));
        }
    }

    public static void logDIDResolutionFailed(Log log, String did, String error) {
        log.error(String.format("[DID Resolution] ✗ Failed to resolve DID %s: %s", did, error));
    }

    public static void logDIDVerificationMethods(Log log, int count) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("[DID Resolution] Verification methods found: %d", count));
        }
    }

    // Issuer Verification Logging

    public static void logIssuerVerificationStart(Log log, String vcFormat) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("\n[%s VC] Starting issuer verification...", vcFormat));
        }
    }

    public static void logIssuerDID(Log log, String vcFormat, String issuerDid) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("[%s VC] Issuer DID: %s", vcFormat, issuerDid));
        }
    }

    public static void logKeyID(Log log, String vcFormat, String kid) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("[%s VC] Key ID (kid): %s", vcFormat, kid));
        }
    }

    public static void logProofType(Log log, String proofType, String verificationMethod) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("[JSON-LD VC] Proof type: %s", proofType));
            log.debug(String.format("[JSON-LD VC] Verification method: %s", verificationMethod));
        }
    }

    public static void logSubject(Log log, String vcFormat, String subject) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("[%s VC] Subject: %s", vcFormat, subject));
        }
    }

    // Trust Policy Logging

    public static void logTrustPolicyCheck(Log log, String issuerDid) {
        if (log.isDebugEnabled()) {
            log.debug("[Trust Policy] Checking if issuer is in allowlist...");
        }
    }

    public static void logTrustPolicyAccepted(Log log) {
        if (log.isDebugEnabled()) {
            log.debug("[Trust Policy] ✓ Issuer is trusted");
        }
    }

    public static void logTrustPolicyRejected(Log log, String issuerDid, String[] trustedIssuers) {
        log.error(String.format("[Trust Policy] ✗ REJECTED - Issuer not in trusted allowlist: %s", issuerDid));
        if (log.isDebugEnabled() && trustedIssuers != null) {
            log.debug("[Trust Policy] Trusted issuers: " + String.join(", ", trustedIssuers));
        }
    }

    // Signature Verification Logging

    public static void logVerificationMethodUsed(Log log, String vcFormat, String methodId, String keyType) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("[%s VC] Using verification method: %s", vcFormat, methodId));
            log.debug(String.format("[%s VC] Key type: %s", vcFormat, keyType));
        }
    }

    public static void logSignatureVerificationStart(Log log, String vcFormat) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("[%s VC] Verifying signature...", vcFormat));
        }
    }

    public static void logSignatureVerificationSuccess(Log log, String vcFormat) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("[%s VC] ✓ Signature verified successfully!", vcFormat));
            log.debug(String.format("[%s VC] ✓ Issuer verification complete", vcFormat));
        }
    }

    public static void logSignatureVerificationFailed(Log log, String vcFormat, String error) {
        log.error(String.format("[%s VC] ✗ Signature verification failed: %s", vcFormat, error));
    }

    // Credential Counting Logging

    public static void logCredentialCount(Log log, int count) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("\n=== [Issuer Verification] Starting issuer verification for all credentials ==="));
            log.debug(String.format("[Issuer Verification] Found %d credential(s) to verify", count));
        }
    }

    public static void logCredentialIndex(Log log, int current, int total) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("\n[Issuer Verification] ========== Credential %d/%d ==========", current, total));
        }
    }

    public static void logCredentialType(Log log, String type) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("[Issuer Verification] Type: %s", type));
        }
    }

    public static void logCredentialVerificationSuccess(Log log, int credentialNum, String issuer, String verificationMethod) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("[Issuer Verification] ✓ Credential %d verified successfully", credentialNum));
            log.debug(String.format("[Issuer Verification] Issuer: %s", issuer));
            log.debug(String.format("[Issuer Verification] Verification Method: %s", verificationMethod));
        }
    }

    public static void logCredentialVerificationFailed(Log log, int credentialNum, String error) {
        log.error(String.format("[Issuer Verification] ✗ Failed to verify credential %d: %s", credentialNum, error));
    }

    public static void logAllCredentialsVerified(Log log, int count) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("\n[Issuer Verification] ✓✓✓ All %d credential(s) verified successfully! ✓✓✓\n", count));
        }
    }

    // VP Submission Logging

    public static void logVPSubmissionStart(Log log) {
        if (log.isDebugEnabled()) {
            log.debug("\n=== [VP Response] POST /openid4vp/v1/response ===");
        }
    }

    public static void logVPTokenFormat(Log log, String format) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("[VP Token] Format: %s", format));
        }
    }

    public static void logStateValidation(Log log, boolean valid) {
        if (valid) {
            log.debug("✓ State validated successfully");
        } else {
            log.error("✗ Invalid or expired state");
        }
    }

    public static void logNonceValidation(Log log, String expected, String received) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("[Nonce] Expected: %s", expected));
            log.debug(String.format("[Nonce] Received: %s", received));
        }
    }

    public static void logVPVerificationComplete(Log log) {
        if (log.isDebugEnabled()) {
            log.debug("\n=== VP Verification Complete ===\n");
        }
    }

    // Error Logging

    public static void logError(Log log, String component, String message) {
        log.error(String.format("[%s] ERROR: %s", component, message));
    }

    public static void logWarning(Log log, String component, String message) {
        log.warn(String.format("[%s] WARNING: %s", component, message));
    }

    // Generic Logging

    public static void logDebug(Log log, String component, String message) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("[%s] %s", component, message));
        }
    }

    public static void logInfo(Log log, String component, String message) {
        log.info(String.format("[%s] %s", component, message));
    }
}
