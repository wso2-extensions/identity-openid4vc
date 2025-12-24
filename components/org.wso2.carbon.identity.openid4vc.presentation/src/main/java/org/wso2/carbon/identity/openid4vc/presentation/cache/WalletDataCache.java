/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vc.presentation.cache;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Thread-safe singleton cache for storing VP tokens temporarily.
 * Implements TTL-based expiration mechanism.
 */
public class WalletDataCache {

    private static final Log log = LogFactory.getLog(WalletDataCache.class);
    private static final WalletDataCache INSTANCE = new WalletDataCache();
    private static final long DEFAULT_TTL_MINUTES = 5;
    private static final long CLEANUP_INTERVAL_MINUTES = 1;

    private final Map<String, CacheEntry> tokenCache;
    private final Map<String, ContextCacheEntry> contextCache;
    private final ScheduledExecutorService cleanupScheduler;

    /**
     * Private constructor for singleton pattern.
     */
    private WalletDataCache() {
        this.tokenCache = new ConcurrentHashMap<>();
        this.contextCache = new ConcurrentHashMap<>();
        this.cleanupScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "WalletDataCache-Cleanup");
            thread.setDaemon(true);
            return thread;
        });
        startCleanupTask();
    }

    /**
     * Get singleton instance.
     *
     * @return WalletDataCache instance
     */
    public static WalletDataCache getInstance() {
        return INSTANCE;
    }

    /**
     * Store VP token with state as key.
     *
     * @param state    State parameter
     * @param vpToken  VP token to store
     */
    public void storeToken(String state, String vpToken) {
        if (state == null || state.trim().isEmpty()) {
            log.warn("Attempted to store token with null or empty state");
            return;
        }
        if (vpToken == null || vpToken.trim().isEmpty()) {
            log.warn("Attempted to store null or empty VP token");
            return;
        }

        long expiryTime = System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(DEFAULT_TTL_MINUTES);
        tokenCache.put(state, new CacheEntry(vpToken, expiryTime));

        if (log.isDebugEnabled()) {
            log.debug("Stored VP token for state: " + state);
        }
    }

    /**
     * Check if token exists for given state (without removing).
     *
     * @param state State parameter
     * @return true if token exists and not expired, false otherwise
     */
    public boolean hasToken(String state) {
        if (state == null || state.trim().isEmpty()) {
            return false;
        }

        CacheEntry entry = tokenCache.get(state);
        if (entry == null) {
            return false;
        }

        if (entry.isExpired()) {
            tokenCache.remove(state);
            return false;
        }

        return true;
    }

    /**
     * Retrieve and remove VP token (single-use).
     *
     * @param state State parameter
     * @return VP token or null if not found/expired
     */
    public String retrieveToken(String state) {
        if (state == null || state.trim().isEmpty()) {
            log.warn("Attempted to retrieve token with null or empty state");
            return null;
        }

        CacheEntry entry = tokenCache.remove(state);
        if (entry == null) {
            if (log.isDebugEnabled()) {
                log.debug("No token found for state: " + state);
            }
            return null;
        }

        if (entry.isExpired()) {
            log.warn("Token expired for state: " + state);
            return null;
        }

        if (log.isDebugEnabled()) {
            log.debug("Retrieved and removed VP token for state: " + state);
        }
        return entry.getToken();
    }

    /**
     * Store authentication context with sessionDataKey as key.
     *
     * @param sessionDataKey Session data key
     * @param context        Authentication context to store
     */
    public void storeContext(String sessionDataKey, AuthenticationContext context) {
        if (sessionDataKey == null || sessionDataKey.trim().isEmpty()) {
            log.warn("Attempted to store context with null or empty sessionDataKey");
            return;
        }
        if (context == null) {
            log.warn("Attempted to store null context");
            return;
        }

        long expiryTime = System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(DEFAULT_TTL_MINUTES);
        contextCache.put(sessionDataKey, new ContextCacheEntry(context, expiryTime));

        if (log.isDebugEnabled()) {
            log.debug("Stored authentication context for sessionDataKey: " + sessionDataKey);
        }
    }

    /**
     * Retrieve authentication context (without removing).
     *
     * @param sessionDataKey Session data key
     * @return Authentication context or null if not found/expired
     */
    public AuthenticationContext getContext(String sessionDataKey) {
        if (sessionDataKey == null || sessionDataKey.trim().isEmpty()) {
            log.warn("Attempted to retrieve context with null or empty sessionDataKey");
            return null;
        }

        ContextCacheEntry entry = contextCache.get(sessionDataKey);
        if (entry == null) {
            if (log.isDebugEnabled()) {
                log.debug("No context found for sessionDataKey: " + sessionDataKey);
            }
            return null;
        }

        if (entry.isExpired()) {
            log.warn("Context expired for sessionDataKey: " + sessionDataKey);
            contextCache.remove(sessionDataKey);
            return null;
        }

        if (log.isDebugEnabled()) {
            log.debug("Retrieved authentication context for sessionDataKey: " + sessionDataKey);
        }
        return entry.getContext();
    }

    /**
     * Clear authentication context.
     *
     * @param sessionDataKey Session data key
     */
    public void clearContext(String sessionDataKey) {
        if (sessionDataKey == null || sessionDataKey.trim().isEmpty()) {
            return;
        }

        contextCache.remove(sessionDataKey);
        if (log.isDebugEnabled()) {
            log.debug("Cleared authentication context for sessionDataKey: " + sessionDataKey);
        }
    }

    /**
     * Start periodic cleanup task to remove expired entries.
     */
    private void startCleanupTask() {
        cleanupScheduler.scheduleAtFixedRate(() -> {
            try {
                int removedCount = 0;

                // Clean up token cache
                for (Map.Entry<String, CacheEntry> entry : tokenCache.entrySet()) {
                    if (entry.getValue().isExpired()) {
                        tokenCache.remove(entry.getKey());
                        removedCount++;
                    }
                }

                // Clean up context cache
                for (Map.Entry<String, ContextCacheEntry> entry : contextCache.entrySet()) {
                    if (entry.getValue().isExpired()) {
                        contextCache.remove(entry.getKey());
                        removedCount++;
                    }
                }

                if (removedCount > 0 && log.isDebugEnabled()) {
                    log.debug("Cleanup task removed " + removedCount + " expired entries");
                }
            } catch (Exception e) {
                log.error("Error during cache cleanup", e);
            }
        }, CLEANUP_INTERVAL_MINUTES, CLEANUP_INTERVAL_MINUTES, TimeUnit.MINUTES);
    }

    /**
     * Get current cache size (for testing/monitoring).
     *
     * @return Number of entries in cache
     */
    public int size() {
        return tokenCache.size();
    }

    /**
     * Get current context cache size (for testing/monitoring).
     *
     * @return Number of context entries in cache
     */
    public int contextSize() {
        return contextCache.size();
    }

    /**
     * Clear all entries (for testing).
     */
    public void clear() {
        tokenCache.clear();
        contextCache.clear();
        if (log.isDebugEnabled()) {
            log.debug("Cache cleared");
        }
    }

    /**
     * Internal class to store cache entry with expiry time.
     */
    private static class CacheEntry {
        private final String token;
        private final long expiryTime;

        CacheEntry(String token, long expiryTime) {
            this.token = token;
            this.expiryTime = expiryTime;
        }

        String getToken() {
            return token;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expiryTime;
        }
    }

    /**
     * Internal class to store context cache entry with expiry time.
     */
    private static class ContextCacheEntry {
        private final AuthenticationContext context;
        private final long expiryTime;

        ContextCacheEntry(AuthenticationContext context, long expiryTime) {
            this.context = context;
            this.expiryTime = expiryTime;
        }

        AuthenticationContext getContext() {
            return context;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expiryTime;
        }
    }
}

