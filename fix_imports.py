#!/usr/bin/env python3

import re
import sys
from pathlib import Path

def sort_imports(file_path):
    """
    Sort imports in a Java file according to WSO2 checkstyle rules.
    Import groups (separated by blank lines):
    1. com.*
    2. edu.*
    3. org.apache.*
    4. org.wso2.carbon.identity.openid4vc.oid4vp.common.*
    5. org.wso2.carbon.identity.openid4vc.oid4vp.did.*
    6. org.wso2.carbon.identity.openid4vc.oid4vp.presentation.*
    7. org.wso2.carbon.* (other)
    8. java.*
    9. javax.*
    
    Within each group, imports are sorted alphabetically.
    """
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Extract parts: header (before package), package, imports, rest
    package_match = re.search(r'^package\s+[\w.]+;', content, re.MULTILINE)
    if not package_match:
        print(f"No package declaration found in {file_path}")
        return False
    
    package_start = package_match.start()
    package_end = package_match.end()
    
    header = content[:package_start]
    package_line = content[package_start:package_end]
    after_package = content[package_end:]
    
    # Extract imports
    import_section_end = 0
    imports = []
    lines = after_package.split('\n')
    
    in_import_section = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('import '):
            in_import_section = True
            imports.append(stripped)
        elif in_import_section and stripped == '':
            continue  # Skip blank lines in import section
        elif in_import_section and stripped:
            # End of import section
            import_section_end = i
            break
    
    if not imports:
        print(f"No imports found in {file_path}")
        return False
    
    # Group imports according to WSO2 checkstyle rules:
    # Group 1: * (all imports except java/javax)
    # Group 2: java.*
    # Group 3: javax.*
    groups = {
        'other': [],  # all non-java/javax imports
        'java': [],
        'javax': [],
    }
    
    for imp in imports:
        # Extract the package from the import statement
        match = re.match(r'import\s+([\w.]+);', imp)
        if not match:
            continue
        pkg = match.group(1)
        
        if pkg.startswith('java.'):
            groups['java'].append(imp)
        elif pkg.startswith('javax.'):
            groups['javax'].append(imp)
        else:
            groups['other'].append(imp)
    
    # Sort each group alphabetically
    for key in groups:
        groups[key].sort()
    
    # Build sorted import section
    sorted_imports = []
    group_order = ['other', 'java', 'javax']
    
    first_group = True
    for group_key in group_order:
        if groups[group_key]:
            if not first_group:
                sorted_imports.append('')  # Blank line BEFORE each new group (except first)
            sorted_imports.extend(groups[group_key])
            first_group = False
    
    # Reconstruct file
    rest_of_file = '\n'.join(lines[import_section_end:])
    
    new_content = (
        header +
        package_line + '\n\n' +
        '\n'.join(sorted_imports) + '\n\n' +
        rest_of_file
    )
    
    with open(file_path, 'w') as f:
        f.write(new_content)
    
    return True

if __name__ == '__main__':
    files = [
        'components/org.wso2.carbon.identity.openid4vc.oid4vp.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/oid4vp/presentation/authenticator/OpenID4VPAuthenticator.java',
        'components/org.wso2.carbon.identity.openid4vc.oid4vp.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/oid4vp/presentation/dao/impl/PresentationDefinitionDAOImpl.java',
        'components/org.wso2.carbon.identity.openid4vc.oid4vp.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/oid4vp/presentation/dao/impl/VPRequestDAOImpl.java',
        'components/org.wso2.carbon.identity.openid4vc.oid4vp.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/oid4vp/presentation/listener/OpenID4VPIdentityProviderMgtListener.java',
        'components/org.wso2.carbon.identity.openid4vc.oid4vp.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/oid4vp/presentation/polling/LongPollingManager.java',
        'components/org.wso2.carbon.identity.openid4vc.oid4vp.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/oid4vp/presentation/service/impl/DIDDocumentServiceImpl.java',
        'components/org.wso2.carbon.identity.openid4vc.oid4vp.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/oid4vp/presentation/service/impl/PresentationDefinitionServiceImpl.java',
        'components/org.wso2.carbon.identity.openid4vc.oid4vp.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/oid4vp/presentation/service/impl/VPRequestServiceImpl.java',
        'components/org.wso2.carbon.identity.openid4vc.oid4vp.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/oid4vp/presentation/servlet/VPSubmissionServlet.java',
        'components/org.wso2.carbon.identity.openid4vc.oid4vp.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/oid4vp/presentation/servlet/WalletStatusServlet.java',
        'components/org.wso2.carbon.identity.openid4vc.oid4vp.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/oid4vp/presentation/status/StatusNotificationService.java',
    ]
    
    for file_path in files:
        print(f"Sorting imports in {file_path}...")
        if sort_imports(file_path):
            print(f"  ✓ Done")
        else:
            print(f"  ✗ Failed")
