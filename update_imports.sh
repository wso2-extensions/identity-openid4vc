#!/bin/bash
# Script to update all imports in presentation module to point to new modules

PRES_DIR="/Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java"

echo "Updating imports in presentation module..."

# Update model imports
find "$PRES_DIR" -name "*.java" -type f -exec sed -i '' 's/import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.model\./import org.wso2.carbon.identity.openid4vc.oid4vp.common.model./g' {} \;

# Update DTO imports  
find "$PRES_DIR" -name "*.java" -type f -exec sed -i '' 's/import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.dto\./import org.wso2.carbon.identity.openid4vc.oid4vp.common.dto./g' {} \;

# Update exception imports
find "$PRES_DIR" -name "*.java" -type f -exec sed -i '' 's/import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.exception\./import org.wso2.carbon.identity.openid4vc.oid4vp.common.exception./g' {} \;

# Update constant imports
find "$PRES_DIR" -name "*.java" -type f -exec sed -i '' 's/import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.constant\./import org.wso2.carbon.identity.openid4vc.oid4vp.common.constant./g' {} \;

# Update DID service imports
find "$PRES_DIR" -name "*.java" -type f -exec sed -i '' 's/import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.service\.DIDResolverService/import org.wso2.carbon.identity.openid4vc.oid4vp.did.service.DIDResolverService/g' {} \;
find "$PRES_DIR" -name "*.java" -type f -exec sed -i '' 's/import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.service\.DIDDocumentService/import org.wso2.carbon.identity.openid4vc.oid4vp.did.service.DIDDocumentService/g' {} \;

# Update DID provider imports
find "$PRES_DIR" -name "*.java" -type f -exec sed -i '' 's/import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.did\./import org.wso2.carbon.identity.openid4vc.oid4vp.did.provider./g' {} \;

# Update verification service imports
find "$PRES_DIR" -name "*.java" -type f -exec sed -i '' 's/import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.service\.VCVerificationService/import org.wso2.carbon.identity.openid4vc.oid4vp.verification.service.VCVerificationService/g' {} \;
find "$PRES_DIR" -name "*.java" -type f -exec sed -i '' 's/import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.service\.StatusListService/import org.wso2.carbon.identity.openid4vc.oid4vp.verification.service.StatusListService/g' {} \;

# Update common util imports (that moved to common)
find "$PRES_DIR" -name "*.java" -type f -exec sed -i '' 's/import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.util\.OpenID4VPUtil/import org.wso2.carbon.identity.openid4vc.oid4vp.common.util.OpenID4VPUtil/g' {} \;
find "$PRES_DIR" -name "*.java" -type f -exec sed -i '' 's/import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.util\.PresentationDefinitionUtil/import org.wso2.carbon.identity.openid4vc.oid4vp.common.util.PresentationDefinitionUtil/g' {} \;
find "$PRES_DIR" -name "*.java" -type f -exec sed -i '' 's/import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.util\.LogSanitizer/import org.wso2.carbon.identity.openid4vc.oid4vp.common.util.LogSanitizer/g' {} \;
find "$PRES_DIR" -name "*.java" -type f -exec sed -i '' 's/import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.util\.URLValidator/import org.wso2.carbon.identity.openid4vc.oid4vp.common.util.URLValidator/g' {} \;
find "$PRES_DIR" -name "*.java" -type f -exec sed -i '' 's/import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.util\.SecurityUtils/import org.wso2.carbon.identity.openid4vc.oid4vp.common.util.SecurityUtils/g' {} \;
find "$PRES_DIR" -name "*.java" -type f -exec sed -i '' 's/import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.util\.CORSUtil/import org.wso2.carbon.identity.openid4vc.oid4vp.common.util.CORSUtil/g' {} \;

# Update verification util imports
find "$PRES_DIR" -name "*.java" -type f -exec sed -i '' 's/import org\.wso2\.carbon\.identity\.openid4vc\.presentation\.util\.SignatureVerifier/import org.wso2.carbon.identity.openid4vc.oid4vp.verification.util.SignatureVerifier/g' {} \;

echo "Import updates complete!"
