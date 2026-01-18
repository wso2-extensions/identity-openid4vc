-- Database Migration Script for OpenID4VP Trusted Issuers
-- WSO2 Identity Server - OpenID4VP Trusted Issuer Management

-- ====================================================
-- Create Trusted Issuer Table
-- ====================================================

CREATE TABLE IF NOT EXISTS IDN_OPENID4VP_TRUSTED_ISSUER (
    ID INT AUTO_INCREMENT NOT NULL,
    ISSUER_DID VARCHAR(512) NOT NULL,
    TENANT_DOMAIN VARCHAR(255) NOT NULL,
    TENANT_ID INT NOT NULL,
    ADDED_BY VARCHAR(255) NOT NULL,
    ADDED_TIMESTAMP TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    DESCRIPTION VARCHAR(1024),
    IS_ACTIVE BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (ID),
    CONSTRAINT UC_ISSUER_TENANT UNIQUE (ISSUER_DID, TENANT_ID)
);

CREATE INDEX IDX_ISSUER_DID ON IDN_OPENID4VP_TRUSTED_ISSUER(ISSUER_DID);
CREATE INDEX IDX_TENANT_ID ON IDN_OPENID4VP_TRUSTED_ISSUER(TENANT_ID);
CREATE INDEX IDX_IS_ACTIVE ON IDN_OPENID4VP_TRUSTED_ISSUER(IS_ACTIVE);

-- ====================================================
-- Sample Trusted Issuers (Super Tenant)
-- ====================================================

-- Example: Add government identity issuer
-- INSERT INTO IDN_OPENID4VP_TRUSTED_ISSUER 
-- (ISSUER_DID, TENANT_DOMAIN, TENANT_ID, ADDED_BY, DESCRIPTION) 
-- VALUES 
-- ('did:web:government.example.com', 'carbon.super', -1234, 'admin', 'Government Identity Authority');

-- Example: Add university credential issuer
-- INSERT INTO IDN_OPENID4VP_TRUSTED_ISSUER 
-- (ISSUER_DID, TENANT_DOMAIN, TENANT_ID, ADDED_BY, DESCRIPTION) 
-- VALUES 
-- ('did:web:university.example.edu', 'carbon.super', -1234, 'admin', 'State University Credential Issuer');
