package org.wso2.carbon.identity.openid4vc.issuance.credential.validators.proof;

import org.wso2.carbon.identity.openid4vc.issuance.credential.dto.ProofDTO;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;

/**
 * Interface for validating proofs in the credential issuance process.
 */
public interface ProofValidator {

    /**
     * Get the proof type supported by this validator.
     *
     * @return proof type (e.g., "jwt", "attestation")
     */
    String getType();

    /**
     * Validate the proof.
     *
     * @param proofDTO proof details to be validated
     * @param tenantDomain Tenant Domain
     */
    void validateProof(ProofDTO proofDTO, String tenantDomain) throws CredentialIssuanceException;
}
