/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.server.cache;

import org.wso2.carbon.identity.openid4vc.presentation.server.model.StandaloneVerificationSession;

import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory TTL cache for standalone (API-initiated) VP verification sessions.
 * Sessions expire at the timestamp recorded in {@link StandaloneVerificationSession#getExpiresAt()}.
 */
public final class StandaloneVerificationCache {

    private static final StandaloneVerificationCache INSTANCE = new StandaloneVerificationCache();
    private final ConcurrentHashMap<String, StandaloneVerificationSession> sessions =
            new ConcurrentHashMap<>();

    private StandaloneVerificationCache() { }

    public static StandaloneVerificationCache getInstance() { return INSTANCE; }

    public void put(String txnId, StandaloneVerificationSession session) {
        sessions.put(txnId, session);
    }

    public StandaloneVerificationSession get(String txnId) {
        if (txnId == null) {
            return null;
        }
        StandaloneVerificationSession session = sessions.get(txnId);
        if (session == null) {
            return null;
        }
        if (System.currentTimeMillis() > session.getExpiresAt()) {
            sessions.remove(txnId);
            return null;
        }
        return session;
    }

    public void remove(String txnId) {
        sessions.remove(txnId);
    }
}
