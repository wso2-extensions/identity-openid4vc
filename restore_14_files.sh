#!/bin/bash

# Copy only the 14 broken files from the restored directory and update package/imports

FILES=(
    "servlet/VPSubmissionServlet.java"
    "servlet/VCVerificationServlet.java"
    "servlet/WellKnownDIDServlet.java"
    "servlet/WalletStatusServlet.java"
    "servlet/VPDefinitionServlet.java"
    "listener/OpenID4VPIdentityProviderMgtListener.java"
    "polling/LongPollingManager.java"
    "dao/impl/PresentationDefinitionDAOImpl.java"
    "dao/impl/VPRequestDAOImpl.java"
    "internal/VPServiceDataHolder.java"
    "status/StatusNotificationService.java"
    "service/impl/PresentationDefinitionServiceImpl.java"
    "service/impl/VPRequestServiceImpl.java"
    "authenticator/OpenID4VPAuthenticator.java"
)

SRC_DIR="components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation"
DEST_DIR="components/org.wso2.carbon.identity.openid4vc.oid4vp.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/oid4vp/presentation"

for file in "${FILES[@]}"; do
    src_file="$SRC_DIR/$file"
    dest_file="$DEST_DIR/$file"
    
    echo "Processing $file..."
    
    # Update package and imports
    cat "$src_file" | \
        # Update package declaration
        sed 's/^package org\.wso2\.carbon\.identity\.openid4vc\.presentation\./package org.wso2.carbon.identity.openid4vc.oid4vp.presentation./g' | \
        # Update imports: constants, dto, exception, model -> oid4vp.common
        sed 's/^import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.constant\./import org.wso2.carbon.identity.openid4vc.oid4vp.common.constant./g' | \
        sed 's/^import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.dto\./import org.wso2.carbon.identity.openid4vc.oid4vp.common.dto./g' | \
        sed 's/^import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.exception\./import org.wso2.carbon.identity.openid4vc.oid4vp.common.exception./g' | \
        sed 's/^import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.model\./import org.wso2.carbon.identity.openid4vc.oid4vp.common.model./g' | \
        # Update DIDKeyManager import
        sed 's/^import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.util\.DIDKeyManager/import org.wso2.carbon.identity.openid4vc.oid4vp.did.util.DIDKeyManager/g' | \
        # Update OpenID4VPUtil import
        sed 's/^import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.util\.OpenID4VPUtil/import org.wso2.carbon.identity.openid4vc.oid4vp.common.util.OpenID4VPUtil/g' | \
        # Update remaining presentation imports
        sed 's/^import org\.wso2\.carbon\.identity\.openid4vc\.presentation\./import org.wso2.carbon.identity.openid4vc.oid4vp.presentation./g' > "$dest_file"
done

echo "File restoration complete!"
