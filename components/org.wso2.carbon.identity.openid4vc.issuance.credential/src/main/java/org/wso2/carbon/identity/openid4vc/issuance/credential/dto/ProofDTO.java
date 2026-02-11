package org.wso2.carbon.identity.openid4vc.issuance.credential.dto;

import java.util.List;
import java.util.Map;

/**
 * DTO for proof details in the credential issuance process.
 */
public class ProofDTO {

    private String type;
    private List<String> proofs;
    private Map<String, Object> publicKey;
    private String keyId;
    private long issuedAt;
    private String nonce;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Map<String, Object> getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(Map<String, Object> publicKey) {
        this.publicKey = publicKey;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(long issuedAt) {
        this.issuedAt = issuedAt;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public List<String> getProofs() {
        return proofs;
    }

    public void setProofs(List<String> proofs) {
        this.proofs = proofs;
    }
}
