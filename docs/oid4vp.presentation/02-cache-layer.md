# 02 — Cache Layer

The presentation module uses **three independent in-memory caches**, each a singleton backed by `ConcurrentHashMap`. None of these caches are distributed — they exist only within a single JVM, which means this module **does not support clustered deployments** without modification.

---

## 1. VPRequestCache (322 lines)

### Purpose
Stores active `VPRequest` objects during the authentication flow. This is the **primary storage** for VP requests — the `VPRequestDAOImpl` delegates entirely to this cache.

### Singleton Pattern
Double-checked locking with `volatile`:

```java
private static volatile VPRequestCache instance;
public static VPRequestCache getInstance() {
    if (instance == null) {
        synchronized (VPRequestCache.class) {
            if (instance == null) { instance = new VPRequestCache(); }
        }
    }
    return instance;
}
```

### Internal Data Structures

| Field | Type | Purpose |
|---|---|---|
| `cache` | `ConcurrentHashMap<String, VPRequestCacheEntry>` | requestId → entry |
| `transactionToRequestIdMap` | `ConcurrentHashMap<String, String>` | transactionId → requestId |

### `VPRequestCacheEntry` (inner class)

```java
class VPRequestCacheEntry {
    VPRequest vpRequest;
    long createdAt;    // System.currentTimeMillis()
    long expiresAt;    // createdAt + TTL
}
```

### TTL & Cleanup

- **TTL**: Read from `OpenID4VPConstants.Defaults.CACHE_ENTRY_EXPIRY_SECONDS` (default 300s = 5 min)
- **Cleanup thread**: `ScheduledExecutorService` runs every **60 seconds**
- **LRU Eviction**: When cache reaches max capacity, evicts the **oldest 10%** of entries (sorted by `createdAt`)

### Key Operations

| Method | Behavior |
|---|---|
| `put(requestId, vpRequest)` | Wraps in `VPRequestCacheEntry`, stores in both maps |
| `get(requestId)` | Returns null if expired, otherwise returns the `VPRequest` |
| `getByTransactionId(txnId)` | Looks up requestId from index map, then fetches |
| `updateStatus(requestId, status)` | Mutates the cached `VPRequest.setStatus()` in-place |
| `updateJwt(requestId, jwt)` | Mutates `VPRequest.setRequestJwt()` in-place |
| `remove(requestId)` | Removes from both maps |
| `cleanup()` | Iterates all entries, removes expired ones, runs LRU eviction if at capacity |

### Code Review Notes
- **In-place mutation**: `updateStatus()` and `updateJwt()` directly mutate the `VPRequest` object stored in the cache. If any code holds a reference to that `VPRequest`, it will see the mutation — this could be intentional (avoiding copy overhead) but violates immutability principles.
- **No max-size enforcement on put**: LRU eviction only happens during cleanup, not on `put()`. A burst of requests could exceed the configured max.
- **Daemon thread**: The cleanup executor is not shut down on bundle deactivation.

---

## 2. VPStatusListenerCache (431 lines)

### Purpose
Manages long-polling listeners. When the browser polls for VP submission status, a `StatusCallback` is registered here. When the wallet submits a VP, this cache is notified and triggers the callback, releasing the polling thread.

### Singleton Pattern
Same double-checked locking as `VPRequestCache`.

### Core Concept: StatusCallback

```java
interface StatusCallback {
    void onStatusChange(String status);            // Status string change
    void onTimeout();                              // Poll timeout
    void onSubmissionReceived(VPSubmission sub);   // Direct VP submission delivery
}
```

### Internal Data Structure

```java
ConcurrentHashMap<String, ConcurrentHashMap<String, StatusListener>> listeners;
// requestId → { listenerId → StatusListener }
```

### `StatusListener` (inner class)

```java
class StatusListener {
    String listenerId;
    StatusCallback callback;
    long registeredAt;
    long timeoutAt;
    volatile boolean notified;     // prevent double-notification
    volatile boolean timedOut;
}
```

### Key Operations

| Method | Behavior |
|---|---|
| `registerListener(requestId, listenerId, timeout, callback)` | Creates `StatusListener`, stores in nested map |
| `notifyListeners(requestId, status)` | Iterates all listeners for that requestId, calls `callback.onStatusChange(status)` on each, sets `notified=true` |
| `notifyListenersWithSubmission(requestId, submission)` | Same but calls `callback.onSubmissionReceived(submission)` — the **direct processing** path |
| `removeListener(requestId, listenerId)` | Removes specific listener |
| `removeAllListeners(requestId)` | Removes all listeners for a request |
| `hasActiveListeners(requestId)` | Checks if any non-timed-out listeners exist |

### Cleanup
- Runs every **10 seconds** (more aggressive than the other caches)
- Removes timed-out listeners, calling `callback.onTimeout()` for each

### Code Review Notes
- **Thread safety**: `notified` and `timedOut` are `volatile` but the notify-and-set-flag operation is not atomic. Two threads could both see `notified=false` and both proceed to notify.
- **Callback exceptions**: Exceptions from callbacks are caught and logged but could leave the listener in an inconsistent state.

---

## 3. WalletDataCache (438 lines)

### Purpose
A multi-purpose temporary store for three types of data:

| Data Type | Map | Use Case |
|---|---|---|
| **VP Tokens** (String) | `tokenCache` | Raw VP token strings |
| **AuthenticationContext** | `contextCache` | Preserving auth context across async flow |
| **VPSubmission** | `submissionCache` | Full submission objects for authenticator fallback |

### Singleton Pattern
Same double-checked locking.

### Internal Data Structure

Each cache type uses its own `ConcurrentHashMap`:

```java
ConcurrentHashMap<String, CacheEntry<String>> tokenCache;
ConcurrentHashMap<String, CacheEntry<AuthenticationContext>> contextCache;
ConcurrentHashMap<String, CacheEntry<VPSubmission>> submissionCache;
```

Where `CacheEntry<T>` wraps:
```java
class CacheEntry<T> {
    T value;
    long createdAt;
    long expiresAt;   // createdAt + 5 minutes
}
```

### TTL
- All entries expire after **5 minutes** (hardcoded)
- Cleanup runs every **60 seconds**

### Key Operations

| Method | Behavior |
|---|---|
| `storeToken(requestId, token)` | Stores raw VP token string |
| `getToken(requestId)` | Returns and **removes** the token (one-time read) |
| `hasToken(requestId)` | Check without removal |
| `storeSubmission(requestId, sub)` | Stores VPSubmission |
| `getSubmission(requestId)` | Returns and **removes** the submission |
| `hasSubmission(requestId)` | Check without removal |
| `storeContext(sessionKey, ctx)` | Stores AuthenticationContext |
| `getContext(sessionKey)` | Returns and **removes** the context |

### Code Review Notes
- **Destructive reads**: `getToken()` and `getSubmission()` remove the entry. This is deliberate (one-time consumption) but means a retry will fail.
- **Hardcoded TTL**: The 5-minute TTL is not configurable, unlike `VPRequestCache` which reads from properties.
- **Three separate maps**: Could be unified with a typed key or a generic cache, reducing code duplication.

---

## Cache Interaction Diagram

```
VPSubmissionServlet                    OpenID4VPAuthenticator
      │                                        │
      │ 1. storeSubmission(requestId, sub)     │
      │───────────►WalletDataCache              │
      │                                        │
      │ 2. notifyListenersWithSubmission()     │
      │───────────►VPStatusListenerCache        │
      │                  │                     │
      │                  │ 3. callback.         │
      │                  │    onSubmissionReceived()
      │                  │────────────────────► │
      │                                        │
      │                        4. If callback   │
      │                        missed, fallback:│
      │                        getSubmission()  │
      │                  WalletDataCache ◄──────│
```

---

## Summary Table

| Cache | Singleton | TTL | Cleanup Interval | Eviction | Thread-Safe |
|---|---|---|---|---|---|
| `VPRequestCache` | DCL | Configurable (5 min default) | 60s | LRU oldest 10% | `ConcurrentHashMap` + in-place mutation |
| `VPStatusListenerCache` | DCL | Per-listener timeout | 10s | Timeout-based | `volatile` flags (race risk) |
| `WalletDataCache` | DCL | 5 min (hardcoded) | 60s | TTL only | `ConcurrentHashMap` |
