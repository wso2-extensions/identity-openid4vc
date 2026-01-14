# OpenID4VP Logging Enhancements

## Summary
Comprehensive logging has been added to the OpenID4VP presentation component to provide detailed visibility into the VP submission and authentication flow.

## Files Modified

### 1. VPSubmissionServiceImpl.java
**Location:** `src/main/java/org/wso2/carbon/identity/openid4vc/presentation/service/impl/VPSubmissionServiceImpl.java`

**Enhancements:**
- **processVPSubmission()**: Added detailed INFO-level logging for:
  - Entry point with submission details (state, tenant ID, has VP token, has error)
  - VP request fetching and validation
  - Expiration checks
  - Status validation
  - Wallet error detection
  - Submission record creation (submission ID, transaction ID)
  - Database persistence
  - Status updates
  - Success summary with all key IDs

- **processErrorSubmission()**: Added INFO-level logging for:
  - Error submission processing
  - Error code and description
  - Generated IDs
  - Database operations
  - Success confirmation

- **getVPSubmissionById()**: Added DEBUG-level logging for:
  - Query initiation
  - Found/not found status

- **getVPSubmissionByRequestId()**: Added DEBUG-level logging for:
  - Query initiation
  - Found/not found status

**Log Prefix:** `[VP_SUBMISSION]` and `[VP_ERROR_SUBMISSION]`

### 2. VPSubmissionDAOImpl.java
**Location:** `src/main/java/org/wso2/carbon/identity/openid4vc/presentation/dao/impl/VPSubmissionDAOImpl.java`

**Enhancements:**
- **createVPSubmission()**: Added INFO-level logging for:
  - Database operation initiation
  - Submission ID, Request ID, Tenant ID
  - Rows affected
  - SQL errors with full exception details
  - Database errors

- **getVPSubmissionById()**: Added DEBUG-level logging for:
  - Query initiation
  - Found/not found status
  - Database errors

- **getVPSubmissionByRequestId()**: Added DEBUG-level logging for:
  - Query initiation
  - Found/not found status
  - Database errors

**Log Prefix:** `[VP_SUBMISSION_DAO]` and `[VP_SUBMISSION_QUERY]`

### 3. VPRequestDAOImpl.java
**Location:** `src/main/java/org/wso2/carbon/identity/openid4vc/presentation/dao/impl/VPRequestDAOImpl.java`

**Enhancements:**
- **updateVPRequestStatus()**: Added INFO-level logging for:
  - Status update initiation
  - Request ID, new status, tenant ID
  - Rows affected
  - Warning if no rows updated (request may not exist)
  - SQL errors with full exception details
  - Database errors

**Log Prefix:** `[VP_REQUEST_DAO]`

## Log Flow Example

When a VP token is submitted, you will now see logs like this:

```
[VP SUBMISSION SERVLET CALLED]
Request URI: /openid4vp/v1/response

[VP_SUBMISSION] ========== Processing VP Submission ==========
[VP_SUBMISSION] State (Request ID): c62f00f8-2e07-403a-836a-4b354e3d817a
[VP_SUBMISSION] Tenant ID: -1234
[VP_SUBMISSION] Has VP Token: true
[VP_SUBMISSION] Has Error: false
[VP_SUBMISSION] Fetching VP request from database...
[VP_SUBMISSION] VP Request found - Status: ACTIVE
[VP_SUBMISSION] VP Request Expires At: 1736834972506
[VP_SUBMISSION] VP Request validation passed
[VP_SUBMISSION] Creating submission record...
[VP_SUBMISSION] Generated Submission ID: sub_abc123
[VP_SUBMISSION] Generated Transaction ID: txn_def456
[VP_SUBMISSION] Presentation submission included (length: 245 chars)

[VP_SUBMISSION_DAO] Creating VP submission in database...
[VP_SUBMISSION_DAO] Submission ID: sub_abc123
[VP_SUBMISSION_DAO] Request ID: c62f00f8-2e07-403a-836a-4b354e3d817a
[VP_SUBMISSION_DAO] Tenant ID: -1234
[VP_SUBMISSION_DAO] VP submission created successfully - Rows affected: 1

[VP_SUBMISSION] Persisting submission to database...
[VP_SUBMISSION] Submission persisted successfully
[VP_SUBMISSION] Updating request status to VP_SUBMITTED...

[VP_REQUEST_DAO] Updating VP request status...
[VP_REQUEST_DAO] Request ID: c62f00f8-2e07-403a-836a-4b354e3d817a
[VP_REQUEST_DAO] New Status: VP_SUBMITTED
[VP_REQUEST_DAO] Tenant ID: -1234
[VP_REQUEST_DAO] VP request status updated successfully - Rows affected: 1

[VP_SUBMISSION] Request status updated successfully
[VP_SUBMISSION] ========== VP Submission Processed Successfully ==========
[VP_SUBMISSION] Submission ID: sub_abc123
[VP_SUBMISSION] Request ID: c62f00f8-2e07-403a-836a-4b354e3d817a
[VP_SUBMISSION] Transaction ID: txn_def456
[VP_SUBMISSION] Verification Status: PENDING
[VP_SUBMISSION] ============================================================
```

## Error Scenarios

### VP Request Not Found
```
[VP_SUBMISSION] Fetching VP request from database...
[VP_SUBMISSION] VP REQUEST NOT FOUND: c62f00f8-2e07-403a-836a-4b354e3d817a
```

### VP Request Expired
```
[VP_SUBMISSION] VP REQUEST EXPIRED: c62f00f8-2e07-403a-836a-4b354e3d817a
[VP_SUBMISSION] Updated request status to EXPIRED
```

### Wallet Error
```
[VP_SUBMISSION] Wallet returned error: access_denied
[VP_SUBMISSION] Error description: User declined the request

[VP_ERROR_SUBMISSION] ========== Processing Wallet Error Submission ==========
[VP_ERROR_SUBMISSION] Request ID: c62f00f8-2e07-403a-836a-4b354e3d817a
[VP_ERROR_SUBMISSION] Error Code: access_denied
[VP_ERROR_SUBMISSION] Error Description: User declined the request
```

### Database Errors
```
[VP_SUBMISSION_DAO] SQL error creating VP submission: Duplicate entry 'sub_abc123'
[VP_SUBMISSION_DAO] Database error creating VP submission: sub_abc123
```

## Benefits

1. **Complete Visibility**: Every step of the VP submission process is now logged
2. **Easy Debugging**: Clear log prefixes make it easy to filter and search
3. **Error Tracking**: All errors are logged with full context and stack traces
4. **Performance Monitoring**: Row counts help identify database issues
5. **Flow Tracing**: Can trace a single submission through the entire flow using request ID

## Log Levels

- **INFO**: Key business operations and state changes
- **DEBUG**: Detailed query operations and lookups
- **WARN**: Unexpected conditions that don't prevent operation
- **ERROR**: Failures that prevent successful operation

## Next Steps

To see these logs in action:
1. Rebuild the component
2. Deploy to WSO2 IS
3. Trigger a VP submission
4. Check the logs in `wso2carbon.log`

You can filter logs using:
```bash
grep "\[VP_" wso2carbon.log
```

Or for specific components:
```bash
grep "\[VP_SUBMISSION\]" wso2carbon.log
grep "\[VP_SUBMISSION_DAO\]" wso2carbon.log
grep "\[VP_REQUEST_DAO\]" wso2carbon.log
```
