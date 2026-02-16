#!/bin/bash

# Fix import ordering in presentation module files
# The rule is imports must be alphabetically sorted:
# org.wso2.carbon.identity.openid4vc.oid4vp.common.* comes before
# org.wso2.carbon.identity.openid4vc.oid4vp.presentation.*

cd /Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.oid4vp.presentation/src/main/java

for file in \
    org/wso2/carbon/identity/openid4vc/oid4vp/presentation/servlet/VPSubmissionServlet.java \
    org/wso2/carbon/identity/openid4vc/oid4vp/presentation/servlet/VCVerificationServlet.java \
    org/wso2/carbon/identity/openid4vc/oid4vp/presentation/servlet/WellKnownDIDServlet.java \
    org/wso2/carbon/identity/openid4vc/oid4vp/presentation/servlet/WalletStatusServlet.java \
    org/wso2/carbon/identity/openid4vc/oid4vp/presentation/servlet/VPDefinitionServlet.java \
    org/wso2/carbon/identity/openid4vc/oid4vp/presentation/listener/OpenID4VPIdentityProviderMgtListener.java \
    org/wso2/carbon/identity/openid4vc/oid4vp/presentation/polling/LongPollingManager.java \
    org/wso2/carbon/identity/openid4vc/oid4vp/presentation/dao/impl/PresentationDefinitionDAOImpl.java \
    org/wso2/carbon/identity/openid4vc/oid4vp/presentation/dao/impl/VPRequestDAOImpl.java \
    org/wso2/carbon/identity/openid4vc/oid4vp/presentation/internal/VPServiceDataHolder.java \
    org/wso2/carbon/identity/openid4vc/oid4vp/presentation/status/StatusNotificationService.java \
    org/wso2/carbon/identity/openid4vc/oid4vp/presentation/service/impl/PresentationDefinitionServiceImpl.java \
    org/wso2/carbon/identity/openid4vc/oid4vp/presentation/service/impl/VPRequestServiceImpl.java \
    org/wso2/carbon/identity/openid4vc/oid4vp/presentation/authenticator/OpenID4VPAuthenticator.java
do
    echo "Sorting imports in $file..."
    
    # Extract package line number
    pkg_line=$(grep -n "^package " "$file" | cut -d: -f1)
    
    # Extract the block of imports
    import_start=$(awk '/^import / {print NR; exit}' "$file")
    import_end=$(awk '/^import / {last=NR} END {print last}' "$file")
    
    if [ -n "$import_start" ] && [ -n "$import_end" ]; then
        # Extract content before imports
        head -n $((import_start - 1)) "$file" > "$file.tmp"
        
        # Extract and sort imports (grouped)
        sed -n "${import_start},${import_end}p" "$file" | \
            grep "^import " | \
            sort | \
            >> "$file.tmp"
        
        # Add blank line after imports
        echo "" >> "$file.tmp"
        
        # Extract content after imports
        tail -n +$((import_end + 1)) "$file" >> "$file.tmp"
        
        # Replace original file
        mv "$file.tmp" "$file"
    fi
done

echo "Import sorting complete!"
