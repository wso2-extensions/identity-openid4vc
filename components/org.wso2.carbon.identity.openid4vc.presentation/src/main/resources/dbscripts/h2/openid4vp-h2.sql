-- =====================================================================
-- OpenID4VP Database Schema for H2 (WSO2 Identity Server)
-- Combined schema for all OpenID4VP tables
-- Run this script against the WSO2_CARBON_DB H2 database
-- =====================================================================


-- ---------------------------------------------------------------------
-- Table: IDN_PRESENTATION_DEFINITION
-- Description: Stores presentation definition templates
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS IDN_PRESENTATION_DEFINITION (
    DEFINITION_ID VARCHAR(255) NOT NULL,
    RESOURCE_ID VARCHAR(255),
    NAME VARCHAR(255) NOT NULL,
    DESCRIPTION CLOB,
    DEFINITION_JSON CLOB NOT NULL,
    TENANT_ID INTEGER DEFAULT -1234,
    PRIMARY KEY (DEFINITION_ID),
    UNIQUE (NAME, TENANT_ID)
);

-- Indexes for PRESENTATION_DEFINITION table
-- idx_pres_def_default removed as column is dropped
CREATE INDEX IF NOT EXISTS IDX_PRES_DEF_RESOURCE_ID ON IDN_PRESENTATION_DEFINITION(RESOURCE_ID);


