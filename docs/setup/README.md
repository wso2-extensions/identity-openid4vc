# OID4VP Authenticator Setup Guide

This guide walks through setting up the OpenID4VP authenticator in WSO2 Identity Server to authenticate users via Verifiable Credentials from a digital wallet.

## Prerequisites

- WSO2 Identity Server 7.x (built from `identity-openid4vc` repo)
- A compatible wallet app (e.g., SpruceID, Walt.id)
- An OID4VCI issuer that has issued credentials to the wallet

---

## Step 1: Build and Deploy the OID4VP Bundles

```bash
cd identity-openid4vc
mvn clean install -DskipTests
```

Copy the 4 OSGi bundles to the IS dropins directory:

```bash
DROPINS=$IS_HOME/repository/components/dropins

cp components/org.wso2.carbon.identity.openid4vc.oid4vp.common/target/*.jar $DROPINS/
cp components/org.wso2.carbon.identity.openid4vc.oid4vp.did/target/*.jar $DROPINS/
cp components/org.wso2.carbon.identity.openid4vc.oid4vp.verification/target/*.jar $DROPINS/
cp components/org.wso2.carbon.identity.openid4vc.oid4vp.presentation/target/*.jar $DROPINS/
```

Also copy required third-party dependencies (`jayway-jsonpath`, `nimbus-jose-jwt`, `bouncy-castle`, `zxing`) if not already present.

---

## Step 2: Configure `deployment.toml`

Add the following to `$IS_HOME/repository/conf/deployment.toml`:

```toml
[server]
hostname = "localhost"
node_ip = "127.0.0.1"
base_path = "https://$ref{server.hostname}:${carbon.management.port}"

# CORS - allow wallet and frontend origins
[cors]
allowed_origins = [
    "https://localhost:9000",
    "https://localhost:9001",
    "http://localhost:5173"
]
supports_credentials = true
supported_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
```

> **Note:** If using ngrok for external wallet access, set `hostname` to your ngrok URL and add `[transport.https.properties] proxyPort = 443`.

---

## Step 3: Create an Identity Provider (Connection)

1. Log in to WSO2 IS Console: `https://localhost:9443/console`
2. Navigate to **Connections** → **New Connection**
3. Select **"Wallet (OpenID4VP)"** authenticator
4. Configure the connection:

| Property | Value |
|----------|-------|
| **Name** | `Wallet Login` |
| **Presentation Definition ID** | _(will be set in Step 4)_ |
| **DID Method** | `did:key` |
| **Response Mode** | `direct_post` |
| **Timeout** | `300` |

5. Click **Register**

---

## Step 4: Create a Presentation Definition

Use the Postman collection or `curl` to create a presentation definition:

```bash
curl -k -X POST https://localhost:9443/openid4vp/v1/presentation-definitions \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  -d '{
    "name": "University Credential",
    "purpose": "Verify your university credential",
    "definition": {
      "id": "university-credential-def",
      "name": "University Credential Verification",
      "purpose": "Verify your university credential",
      "input_descriptors": [
        {
          "id": "university-credential",
          "name": "University Credential",
          "purpose": "We need to verify your university credential",
          "format": {
            "vc+sd-jwt": {}
          },
          "constraints": {
            "fields": [
              {
                "path": ["$.vct"],
                "filter": {
                  "type": "string",
                  "const": "UniversityDegreeCredential"
                }
              },
              {
                "path": ["$.email"]
              }
            ]
          }
        }
      ]
    }
  }'
```

Copy the returned `id` and update the Identity Provider's **Presentation Definition ID** property.

---

## Step 5: Configure Claim Mappings

1. Go to **Connections** → **Wallet Login** → **Attributes**
2. Under **Attribute Mappings**, add:

| IDP Claim (from VC) | Local Claim |
|---------------------|-------------|
| `email` | `http://wso2.org/claims/emailaddress` |
| `alumniOf` | `http://wso2.org/claims/department` |
| `degree.name` | `http://wso2.org/claims/title` |
| `degree.type` | `http://wso2.org/claims/organization` |

3. Set **User ID Claim** to `email` (or whichever claim uniquely identifies users)

> The authenticator supports dotted paths (e.g., `degree.name`) for nested claims within `credentialSubject`.

---

## Step 6: Register a Service Provider Application

1. Navigate to **Applications** → **New Application**
2. Create a **Standard-Based Application** (OIDC)
3. Configure:
   - **Name:** `My WebApp`
   - **Protocol:** OIDC
   - **Callback URL:** `http://localhost:5173/callback` (or your app's URL)
   - **Allowed Grant Types:** Authorization Code
4. Under **Login Flow** → add **Wallet (OpenID4VP)** as a federated authenticator step
5. Under **User Attributes**, request the claims you need (e.g., email)

---

## Step 7: Deploy the Login Page

Ensure the wallet login JSP page exists at:

```
$IS_HOME/repository/deployment/server/webapps/authenticationendpoint/wallet_login.jsp
```

This page should:
- Display the QR code for wallet scanning
- Poll `/openid4vp/v1/wallet-status/{requestId}` for status updates
- Redirect back to IS on successful VP submission

---

## Step 8: Test the Flow

1. Start WSO2 IS: `$IS_HOME/bin/wso2server.sh`
2. Open your web application
3. Click **Login** → redirected to WSO2 IS
4. Select **Wallet (OpenID4VP)** login option
5. Scan the QR code with your wallet app
6. The wallet submits the Verifiable Presentation
7. WSO2 IS verifies the VP, extracts claims, maps them, and issues an ID token

### Expected ID Token
```json
{
  "sub": "user@example.com",
  "email": "user@example.com",
  "amr": ["OpenID4VPAuthenticator"],
  "iss": "https://localhost:9443/oauth2/token",
  ...
}
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| QR code not loading | VP request creation failed | Check IS logs for errors |
| Wallet returns error | Invalid `request_uri` or expired request | Ensure IS is reachable from wallet |
| Claims missing in ID token | Claim mappings not configured | Check Step 5 claim mappings |
| `NullPointerException` on `vpToken` | Wallet submitted empty token | Ensure wallet sends `vp_token` |
| CORS error | Missing origin | Add wallet origin to `deployment.toml` CORS config |

---

## API Endpoint Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/openid4vp/v1/vp-request` | POST | Create VP request |
| `/openid4vp/v1/request-uri/{id}` | GET | Fetch authorization request JWT |
| `/openid4vp/v1/response` | POST | Wallet submits VP (direct_post) |
| `/openid4vp/v1/vp-status/{id}/status` | GET | Poll VP request status |
| `/openid4vp/v1/wallet-status/{id}` | GET | Login page polls for completion |
| `/openid4vp/v1/presentation-definitions` | CRUD | Manage presentation definitions |
| `/openid4vp/v1/vc-verification` | POST | Verify a VC |
| `/.well-known/did.json` | GET | Verifier DID document |
