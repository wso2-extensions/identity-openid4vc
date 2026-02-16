import os
import re

def remove_logs(file_path):
    with open(file_path, 'r') as f:
        content = f.read()

    original_content = content
    
    # 1. Remove Imports
    content = re.sub(r'import\s+org\.apache\.commons\.logging\..*?;\s*', '', content)
    content = re.sub(r'import\s+org\.wso2\.carbon\.identity\.openid4vc\.presentation\.util\.LogSanitizer;?.*?\n', '', content)

    # 2. Remove Logger Fields
    content = re.sub(r'private\s+static\s+final\s+Log\s+\w+\s*=\s*LogFactory\.getLog\(.*?\);(\s*)', '', content)
    content = re.sub(r'private\s+static\s+final\s+String\s+LOG_PREFIX\s*=\s*".*?";(\s*)', '', content)

    # 3. Remove Log Statements (smart removal)
    while True:
        match = re.search(r'\b(log|LOG)\.(debug|info|warn|error|trace|fatal)\s*\(', content)
        if not match:
            break
            
        start_index = match.start()
        
        balance = 0
        in_string = False
        escape = False
        end_index = -1
        
        # We start searching for the TERMINATING semicolon from the start_index.
        # But we must ensure we have closed the parenthesis first.
        # Logic:
        # scan until ';' is found AND balance == 0 AND we have seen at least one '(' (which is guaranteed by regex)
        
        # Actually, the regex matched '('. So balance starts at 1 effectively after the match? 
        # No, let's scan from start_index.
        
        i = start_index
        length = len(content)
        paren_seen = False
        
        while i < length:
            char = content[i]
            
            if escape:
                escape = False
                i += 1
                continue
                
            if char == '\\':
                escape = True
            elif char == '"' and not in_string: 
                in_string = True
            elif char == '"' and in_string: 
                in_string = False
            
            if not in_string:
                if char == '(':
                    balance += 1
                    paren_seen = True
                elif char == ')':
                    balance -= 1
                elif char == ';' and balance == 0 and paren_seen:
                    end_index = i
                    break
            
            i += 1
        
        if end_index != -1:
            remove_end = end_index + 1
            # Consume trailing newline if present to avoid blank lines
            if remove_end < len(content) and content[remove_end] == '\n':
                remove_end += 1
            
            content = content[:start_index] + content[remove_end:]
        else:
            print(f"FAILED to find end of log statement in {file_path} at index {start_index}")
            break

    if content != original_content:
        with open(file_path, 'w') as f:
            f.write(content)
        return True
    return False

def main():
    root_dir = "/Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation"
    
    print(f"Scanning {root_dir}...")
    
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.endswith(".java") and filename != "OpenID4VPAuthenticator.java":
                path = os.path.join(dirpath, filename)
                try:
                    if remove_logs(path):
                        print(f"Processed: {filename}")
                except Exception as e:
                    print(f"Error processing {filename}: {e}")

if __name__ == "__main__":
    main()
