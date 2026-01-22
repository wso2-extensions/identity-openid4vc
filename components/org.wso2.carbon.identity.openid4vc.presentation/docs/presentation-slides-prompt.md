# AI Prompt for OID4VP Presentation Slides

Copy and paste the prompt below into an AI slide generator (e.g., Gamma, Beautiful.ai, ChatGPT + Canva plugin, or Claude).

---

## Prompt

```
Create a professional presentation with 20-25 slides on the topic:

"OpenID for Verifiable Presentations (OID4VP) - Concepts and WSO2 Identity Server Implementation"

Target audience: Software developers, architects, and product managers.
Duration: 45 minutes + 15 min demo.
Design style: Modern, clean, tech-focused. Use dark theme with orange (#FF7300) as accent color. Include diagrams and icons.

---

SECTION 1: Introduction to Verifiable Credentials (4 slides)

Slide 1 - Title Slide:
- Title: "OpenID for Verifiable Presentations (OID4VP)"
- Subtitle: "Concepts and WSO2 Identity Server Implementation"
- Include WSO2 logo

Slide 2 - Problem Statement:
- Traditional identity systems are centralized and siloed
- Users have no control over their data
- No cryptographic verification of claims
- Privacy concerns with sharing entire documents
- Include visual: fragmented data silos

Slide 3 - W3C Verifiable Credentials Model:
- Diagram showing: Issuer → Holder → Verifier triangle
- Define: Issuer (trusted entity), Holder (user wallet), Verifier (service)
- Mention: DIDs as verification keys

Slide 4 - VC/VP Structure:
- Show JSON example of a Verifiable Credential
- Highlight: @context, type, issuer, credentialSubject, proof
- Simple visual of credential card

---

SECTION 2: OID4VP Protocol Deep Dive (6 slides)

Slide 5 - Why OID4VP?:
- Standard protocol for requesting/presenting VCs
- Based on OAuth 2.0 - familiar patterns
- Cross-platform wallet compatibility
- Supports selective disclosure

Slide 6 - Protocol Flow Overview:
- Sequence diagram:
  1. Relying Party shows QR code
  2. User scans with wallet
  3. Wallet fetches request object
  4. User selects credentials
  5. Wallet submits VP
  6. RP verifies and grants access

Slide 7 - Key Protocol Parameters:
- Table with parameters:
  - client_id: Verifier identifier (DID)
  - response_type: vp_token
  - response_mode: direct_post
  - nonce: Replay protection
  - presentation_definition: What to request

Slide 8 - Presentation Definition:
- JSON example showing input_descriptors
- Explain: constraints, fields, filters
- Purpose: Define exactly what credentials to request

Slide 9 - VP Response Format:
- Show vp_token and presentation_submission structure
- Explain descriptor_map mapping

Slide 10 - Supported Formats:
- Table: jwt_vc_json ✅, jwt_vp ✅, vc+sd-jwt ✅, ldp_vc ⚠️

---

SECTION 3: WSO2 IS Implementation (5 slides)

Slide 11 - Architecture Overview:
- Layered architecture diagram:
  - Authentication Layer (OpenID4VPAuthenticator, wallet_login.jsp)
  - API Layer (request, request-uri, response, status endpoints)
  - Service Layer (VPRequestService, VPSubmissionService, VCVerificationService)
  - Data Layer (PostgreSQL/H2)

Slide 12 - Database Schema:
- ER diagram showing:
  - IDN_VP_REQUEST (id, nonce, state, status, expires_at)
  - IDN_VP_SUBMISSION (id, request_id, vp_token)
  - IDN_PRESENTATION_DEFINITION (id, name, definition_json)

Slide 13 - Authentication Flow:
- Detailed sequence diagram:
  1. Browser → IS: Login request
  2. IS creates VP Request
  3. IS returns QR code page
  4. Wallet scans, fetches request
  5. Wallet submits VP
  6. IS verifies, updates status
  7. Browser polls, redirects

Slide 14 - Key Components:
- Table:
  - OpenID4VPAuthenticator: Auth framework integration
  - VPRequestServlet: Create requests
  - VPSubmissionServlet: Handle submissions
  - VCVerificationService: Signature verification
  - SignatureVerifier: Ed25519, ES256, RS256

Slide 15 - Verification Pipeline:
- Flowchart:
  Decode JWT → Extract VCs → Resolve DID → Verify Signature → Check Expiry → Check Revocation → Match Constraints → ACCEPT/REJECT

---

SECTION 4: Live Demo (3 slides)

Slide 16 - Demo Environment:
- WSO2 IS 7.2
- Inji Wallet (mobile)
- Sample web application
- ngrok for wallet connectivity

Slide 17 - Demo Flow:
- Numbered steps with screenshots placeholders:
  1. Access protected resource
  2. QR code appears
  3. Scan with wallet
  4. Select credential
  5. Approve sharing
  6. Successful login

Slide 18 - What to Watch:
- QR code generation
- Wallet interaction
- Status polling
- Credential extraction
- Authenticated session

---

SECTION 5: Wrap-up (3 slides)

Slide 19 - Feature Support Summary:
- Table showing supported features:
  - Response modes ✅
  - VC formats ✅
  - DID methods ✅
  - Revocation checking ✅
  - Nonce/state validation ✅

Slide 20 - Roadmap:
- SD-JWT improvements
- Offline verification
- More wallet integrations
- Production hardening

Slide 21 - Resources:
- Links to:
  - OID4VP Spec
  - DIF Presentation Exchange
  - W3C VC Data Model
  - WSO2 IS Documentation

Slide 22 - Q&A:
- "Questions?" with contact info

---

VISUAL REQUIREMENTS:
- Use icons for each concept (wallet, QR code, lock, check mark)
- Include mermaid-style diagrams converted to visuals
- Use code blocks for JSON/config examples
- Consistent color scheme: Dark background, orange (#FF7300) accents, white text
- Include speaker notes for each slide
```

---

## Alternative: Gamma.app Specific

For [Gamma.app](https://gamma.app), use this shorter prompt:

```
Create a presentation about "OpenID for Verifiable Presentations (OID4VP) and WSO2 Identity Server Implementation".

Include:
1. Introduction to Verifiable Credentials (Issuer-Holder-Verifier model)
2. OID4VP protocol flow with sequence diagrams
3. WSO2 IS architecture (Authentication, API, Service, Data layers)
4. VP verification pipeline flowchart
5. Live demo steps with Inji Wallet
6. Feature support summary table

Style: Modern tech, dark theme with orange (#FF7300) accent.
Audience: Developers and architects.
Duration: 45 minutes.
Include diagrams, code examples, and icons.
```

---

## Tips for Best Results

1. **Gamma.app** - Best for quick, automated designs
2. **Beautiful.ai** - Best for professional business presentations
3. **Canva + AI** - Best for custom visuals
4. **ChatGPT + DALL-E** - Generate custom diagrams first, then assemble
5. **Marp** - If you prefer Markdown-to-slides with code control
