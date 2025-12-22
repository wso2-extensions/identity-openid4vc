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
    private final ScheduledExecutorService cleanupScheduler;

    /**
     * Private constructor for singleton pattern.
     */
    private WalletDataCache() {
        this.tokenCache = new ConcurrentHashMap<>();
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
     * Start periodic cleanup task to remove expired entries.
     */
    private void startCleanupTask() {
        cleanupScheduler.scheduleAtFixedRate(() -> {
            try {
                int removedCount = 0;
                long currentTime = System.currentTimeMillis();

                for (Map.Entry<String, CacheEntry> entry : tokenCache.entrySet()) {
                    if (entry.getValue().isExpired()) {
                        tokenCache.remove(entry.getKey());
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
     * Clear all entries (for testing).
     */
    public void clear() {
        tokenCache.clear();
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
}

