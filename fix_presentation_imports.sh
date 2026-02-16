#!/bin/bash

# Fix import order in presentation module files
# Move org.wso2.carbon.identity.openid4vc.oid4vp.* imports before org.wso2.carbon.identity.openid4vc.presentation.* imports

cd /Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java

# Process each Java file with import order issues
for file in \
    org/wso2/carbon/identity/openid4vc/presentation/servlet/VPSubmissionServlet.java \
    org/wso2/carbon/identity/openid4vc/presentation/servlet/WellKnownDIDServlet.java \
    org/wso2/carbon/identity/openid4vc/presentation/servlet/WalletStatusServlet.java \
    org/wso2/carbon/identity/openid4vc/presentation/servlet/VPDefinitionServlet.java \
    org/wso2/carbon/identity/openid4vc/presentation/listener/OpenID4VPIdentityProviderMgtListener.java \
    org/wso2/carbon/identity/openid4vc/presentation/did/impl/DIDJwkProvider.java \
    org/wso2/carbon/identity/openid4vc/presentation/did/impl/DIDKeyProvider.java \
    org/wso2/carbon/identity/openid4vc/presentation/did/impl/DIDWebProvider.java \
    org/wso2/carbon/identity/openid4vc/presentation/polling/LongPollingManager.java \
    org/wso2/carbon/identity/openid4vc/presentation/dao/impl/PresentationDefinitionDAOImpl.java \
    org/wso2/carbon/identity/openid4vc/presentation/dao/impl/VPRequestDAOImpl.java \
    org/wso2/carbon/identity/openid4vc/presentation/internal/VPServiceDataHolder.java \
    org/wso2/carbon/identity/openid4vc/presentation/status/StatusNotificationService.java \
    org/wso2/carbon/identity/openid4vc/presentation/service/impl/PresentationDefinitionServiceImpl.java \
    org/wso2/carbon/identity/openid4vc/presentation/service/impl/VPRequestServiceImpl.java \
    org/wso2/carbon/identity/openid4vc/presentation/service/impl/DIDDocumentServiceImpl.java \
    org/wso2/carbon/identity/openid4vc/presentation/authenticator/OpenID4VPAuthenticator.java
do
    echo "Processing $file..."
    
    # Create a temporary file to build new import section
    tmpfile=$(mktemp)
    
    # Extract file content
    cat "$file" > "$tmpfile"
    
    # Use Python to reorder imports properly
    python3 << 'PYTHON_SCRIPT' "$file" "$tmpfile"
import sys
import re

file_path = sys.argv[1]
temp_path = sys.argv[2]

with open(temp_path, 'r') as f:
    content = f.read()

# Find the package declaration and imports section
lines = content.split('\n')
import_start = -1
import_end = -1
package_line = -1

for i, line in enumerate(lines):
    if line.strip().startswith('package '):
        package_line = i
    elif line.strip().startswith('import ') and import_start == -1:
        import_start = i
    elif import_start != -1 and not line.strip().startswith('import ') and line.strip() != '':
        import_end = i
        break

if import_start == -1 or import_end == -1:
    sys.exit(0)  # No imports found

# Extract imports
imports = []
for i in range(import_start, import_end):
    if lines[i].strip().startswith('import '):
        imports.append(lines[i])

# Categorize imports
java_imports = []
javax_imports = []
org_imports = []
other_imports = []

for imp in imports:
    if 'import java.' in imp or 'import java.' in imp:
        java_imports.append(imp)
    elif 'import javax.' in imp:
        javax_imports.append(imp)
    elif 'import org.' in imp:
        org_imports.append(imp)
    else:
        other_imports.append(imp)

# Sort each category
other_imports.sort()
java_imports.sort()
javax_imports.sort()
org_imports.sort()

# Rebuild file with properly ordered imports
new_lines = lines[:package_line+1]
new_lines.append('')
new_lines.extend(other_imports)
if other_imports:
    new_lines.append('')
new_lines.extend(java_imports)
if java_imports:
    new_lines.append('')
new_lines.extend(javax_imports)
if javax_imports:
    new_lines.append('')
new_lines.extend(org_imports)
new_lines.append('')
new_lines.extend(lines[import_end:])

# Write back
with open(temp_path, 'w') as f:
    f.write('\n'.join(new_lines))

PYTHON_SCRIPT
    
    # Replace original file
    mv "$tmpfile" "$file"
done

echo "Import order fixes complete!"
