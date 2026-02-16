#!/bin/bash

# Restore imports for files broken by import sorting script

FILES=(
    "servlet/VPSubmissionServlet"
    "servlet/VCVerificationServlet"
    "servlet/WellKnownDIDServlet"
    "servlet/WalletStatusServlet"
    "servlet/VPDefinitionServlet"
    "listener/OpenID4VPIdentityProviderMgtListener"
    "polling/LongPollingManager"
    "dao/impl/PresentationDefinitionDAOImpl"
    "dao/impl/VPRequestDAOImpl"
    "internal/VPServiceDataHolder"
    "status/StatusNotificationService"
    "service/impl/PresentationDefinitionServiceImpl"
    "service/impl/VPRequestServiceImpl"
    "authenticator/OpenID4VPAuthenticator"
)

BASE_PATH="components/org.wso2.carbon.identity.openid4vc.oid4vp.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/oid4vp/presentation"
OLD_BASE="components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation"

for FILE in "${FILES[@]}"; do
    CURRENT_FILE="${BASE_PATH}/${FILE}.java"
    OLD_FILE="${OLD_BASE}/${FILE}.java"
    
    echo "Restoring imports for $FILE..."
    
    # Get original imports from git
    IMPORTS=$(git show HEAD:"${OLD_FILE}" | sed -n '/^import /p' | \
        # Update package names from presentation.* to oid4vp.*
        sed 's/org\.wso2\.carbon\.identity\.openid4vc\.presentation\.constant\./org.wso2.carbon.identity.openid4vc.oid4vp.common.constant./g' | \
        sed 's/org\.wso2\.carbon\.identity\.openid4vc\.presentation\.dto\./org.wso2.carbon.identity.openid4vc.oid4vp.common.dto./g' | \
        sed 's/org\.wso2\.carbon\.identity\.openid4vc\.presentation\.exception\./org.wso2.carbon.identity.openid4vc.oid4vp.common.exception./g' | \
        sed 's/org\.wso2\.carbon\.identity\.openid4vc\.presentation\.model\./org.wso2.carbon.identity.openid4vc.oid4vp.common.model./g' | \
        sed 's/org\.wso2\.carbon\.identity\.openid4vc\.presentation\.util\.DIDKeyManager/org.wso2.carbon.identity.openid4vc.oid4vp.did.util.DIDKeyManager/g' | \
        sed 's/org\.wso2\.carbon\.identity\.openid4vc\.presentation\.util\.OpenID4VPUtil/org.wso2.carbon.identity.openid4vc.oid4vp.common.util.OpenID4VPUtil/g' | \
        sed 's/org\.wso2\.carbon\.identity\.openid4vc\.presentation\./org.wso2.carbon.identity.openid4vc.oid4vp.presentation./g')
    
    # Create temp file with proper structure
    {
        # Copyright header (everything before package)
        awk '/^package / {exit} {print}' "$CURRENT_FILE"
        # Package line
        grep "^package " "$CURRENT_FILE"
        # Blank line
        echo ""
        # Imports
        echo "$IMPORTS"
        # Blank line
        echo ""
        # Everything after package line and first blank lines (class content)
        awk '/^package / {p=1; next} p && NF>0 {p=0; print} p {next} !p && NF>0' "$CURRENT_FILE"
    } > "${CURRENT_FILE}.new"
    
    # Replace original file
    mv "${CURRENT_FILE}.new" "$CURRENT_FILE"
done

echo "Import restoration complete!"
