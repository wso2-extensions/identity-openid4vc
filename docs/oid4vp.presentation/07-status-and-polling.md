# 07 — Status & Polling Layer

This layer handles the **asynchronous coordination** between the browser (waiting for wallet response) and the wallet (submitting VP). It uses a `CountDownLatch`-based long-polling pattern and a state machine for status transitions.

---

## 1. LongPollingManager (325 lines)

### Purpose
Coordinates long-polling requests. When the browser polls for status, this manager blocks the thread until either the wallet submits a VP or the timeout expires.

### Singleton
Double-checked locking. Holds references to `VPStatusListenerCache`, `WalletDataCache`, and `VPRequestDAOImpl`.

### Core Method: `waitForStatusChange(requestId, timeoutMs, tenantId)`

```
1. normalizeTimeout(timeoutMs)
   └── Clamp to [5000ms, 120000ms], default 5000ms

2. checkCurrentStatus(requestId, tenantId) → PollingResult
   └── If already complete (VP submitted, expired, etc.) → return immediately

3. Create CountDownLatch(1)
4. Create PollingResultHolder (volatile wrapper)
5. Register StatusCallback on VPStatusListenerCache:
   └── onStatusChange(status) → set result, latch.countDown()
   └── onTimeout()             → set timeout result, latch.countDown()

6. latch.await(timeout, MILLISECONDS)
   └── If interrupted → return error result
   └── If timed out   → return timeout result
   └── If completed   → return result from callback

7. finally: removeListener()
```

### Immediate Status Check: `checkCurrentStatus(requestId, tenantId)`

Checks multiple sources without blocking:

```
1. WalletDataCache.hasToken(requestId)?     → SUBMITTED
2. WalletDataCache.hasSubmission(requestId)? → SUBMITTED
3. VPRequestDAO.getVPRequestById(requestId)?
   ├── VP_SUBMITTED or COMPLETED → SUBMITTED
   ├── EXPIRED                   → EXPIRED
   ├── ACTIVE                    → check if actually expired by time → EXPIRED or WAITING
   └── null                      → NOT_FOUND
```

### `notifySubmission(requestId, status)`

Called by `StatusNotificationService` when a VP is submitted. Delegates to `VPStatusListenerCache.notifyListeners()`, which triggers the callbacks registered by `waitForStatusChange()`.

### Timeout Configuration

| Constant | Value | Description |
|---|---|---|
| `DEFAULT_POLLING_TIMEOUT_MS` | 5,000 | Default if no timeout specified |
| `MIN_POLLING_TIMEOUT_MS` | 5,000 | Minimum allowed |
| `MAX_POLLING_TIMEOUT_MS` | 120,000 | Maximum allowed |

### Listener ID Format
`"poll_" + UUID.substring(0, 12)` — e.g., `"poll_a1b2c3d4e5f6"`

---

## 2. PollingResult (304 lines)

### Purpose
Immutable value object representing the result of a polling operation. Uses the **factory method pattern** exclusively — no public constructor.

### ResultStatus Enum

| Status | `isComplete()` | `isTokenReceived()` | Description |
|---|---|---|---|
| `WAITING` | ❌ | ❌ | VP not yet submitted |
| `SUBMITTED` | ✅ | ✅ | VP submitted successfully |
| `SUBMITTED_WITH_ERROR` | ✅ | ✅ | VP submitted but wallet reported error |
| `EXPIRED` | ✅ | ❌ | Request has expired |
| `NOT_FOUND` | ✅ | ❌ | Request ID not found |
| `TIMEOUT` | ❌ | ❌ | Poll timed out (should poll again) |
| `ERROR` | ✅ | ❌ | System error |

### Factory Methods

```java
PollingResult.waiting(requestId)
PollingResult.submitted(requestId, status)
PollingResult.submittedWithError(requestId, status)
PollingResult.expired(requestId)
PollingResult.notFound(requestId)
PollingResult.timeout(requestId)
PollingResult.error(requestId, errorMessage)
```

### Key Design: `isComplete()` vs `isTimeout()`

- `isComplete() == true` means **stop polling** — the final state is known
- `isTimeout() == true` means **poll again** — the request is still active but no change occurred within the timeout window

This distinction is critical for the browser's polling loop.

---

## 3. StatusNotificationService (230+ lines)

### Purpose
Central coordinator for all status change notifications. Sits between VP submission handling and the polling infrastructure.

### Singleton Pattern
Double-checked locking. Holds references to `VPStatusListenerCache` and `LongPollingManager`.

### Notification Methods

| Method | When Called | Actions |
|---|---|---|
| `notifyVPSubmitted(requestId, submission)` | VP received from wallet | Notifies listener cache + long polling manager + registered listeners |
| `notifySubmissionError(requestId, error, desc)` | VP received with wallet error | Same as above with `_ERROR` suffix |
| `notifyRequestExpired(requestId)` | Request expired | Notifies + removes all listeners |
| `notifyVerificationComplete(requestId, submission)` | Verification done | Notifies with `COMPLETED` status + cleanup |

### Status String Construction

```java
private String buildSubmissionStatus(VPSubmission submission) {
    String base = "VP_SUBMITTED";
    if (submission.hasError()) return base + "_ERROR";
    return base;
}
```

### StatusChangeListener Interface

```java
interface StatusChangeListener {
    void onStatusChange(String requestId, VPRequestStatus newStatus, VPSubmission submission);
}
```

Registered listeners are stored in a `CopyOnWriteArrayList` for thread-safe iteration. Exceptions from listeners are caught and ignored to prevent disrupting the notification flow.

### Dual Notification

When `notifyVPSubmitted()` is called, it notifies **two** systems:
1. `VPStatusListenerCache.notifyListeners(requestId, status)` — triggers long-polling callbacks
2. `LongPollingManager.notifySubmission(requestId, status)` — which internally also calls `VPStatusListenerCache`

⚠️ **This causes double notification** — `VPStatusListenerCache.notifyListeners()` is called twice. The `notified=true` flag on `StatusListener` should prevent actual double-delivery, but it's wasteful.

---

## 4. StatusTransitionManager (250+ lines)

### Purpose
Utility class (no instances) that enforces the VP request status state machine.

### State Machine

```
   ┌──────────┐     wallet submits VP     ┌──────────────┐
   │  ACTIVE   │──────────────────────────→│ VP_SUBMITTED  │
   └──────┬───┘                           └──────┬────────┘
          │                                       │
          │ timeout                               │ verification done
          ▼                                       ▼
   ┌──────────┐                           ┌──────────────┐
   │ EXPIRED   │                           │  COMPLETED    │
   └──────────┘                           └──────────────┘
                                                  │
                              VP_SUBMITTED ──────→│ EXPIRED
                              (not processed)      (timeout)
```

### Valid Transitions Table

| From | Valid Targets |
|---|---|
| `ACTIVE` | `VP_SUBMITTED`, `EXPIRED` |
| `VP_SUBMITTED` | `COMPLETED`, `EXPIRED` |
| `COMPLETED` | *(terminal — none)* |
| `EXPIRED` | *(terminal — none)* |

### Key Methods

| Method | Returns |
|---|---|
| `isValidTransition(from, to)` | `boolean` |
| `getValidNextStates(current)` | `EnumSet<VPRequestStatus>` |
| `isTerminalState(status)` | `true` for COMPLETED/EXPIRED |
| `canAcceptVPSubmission(status)` | `true` only for ACTIVE |
| `transition(from, to)` | Returns `to` if valid, `from` if invalid (lenient) |
| `transitionStrict(from, to)` | Returns `to` if valid, throws `InvalidStatusTransitionException` if invalid |
| `parseStatus(statusStr)` | Handles `_ERROR` suffix stripping |

### `InvalidStatusTransitionException`

```java
class InvalidStatusTransitionException extends Exception {
    VPRequestStatus fromStatus;
    VPRequestStatus toStatus;
}
```

### Code Review Notes

| Issue | Details |
|---|---|
| **`StatusTransitionManager` not enforced** | The state machine is defined but not consistently used. `VPRequestDAOImpl.updateStatus()` and `VPRequestCache.updateStatus()` don't call `StatusTransitionManager.isValidTransition()` before updating. The state machine is advisory, not enforced. |
| **Double notification in `StatusNotificationService`** | Both `notifyListeners` and `notifySubmission` ultimately call `VPStatusListenerCache.notifyListeners()`. The `notified` flag prevents double-delivery but this should be refactored. |
| **Thread blocking** | `LongPollingManager.waitForStatusChange()` blocks the servlet thread. In a high-concurrency scenario, this could exhaust the thread pool. Consider async servlet support (`AsyncContext`). |
| **No back-pressure** | There's no limit on how many concurrent long-polling requests can be active. Each one holds a thread. |
