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

package org.wso2.carbon.identity.openid4vc.presentation.exception;

/**
 * Exception thrown when a presentation definition is not found.
 */
public class PresentationDefinitionNotFoundException extends VPException {

    private static final long serialVersionUID = 1L;
    private static final String DEFAULT_ERROR_CODE = "DEFINITION_NOT_FOUND";

    /**
     * The definition ID that was not found.
     */
    private String definitionId;

    /**
     * Constructor with definition ID.
     *
     * @param defId The definition ID that was not found
     */
    public PresentationDefinitionNotFoundException(final String defId) {

        super(DEFAULT_ERROR_CODE,
                "Presentation definition not found: " + defId);
        this.definitionId = defId;
    }

    /**
     * Constructor with definition ID and custom message.
     *
     * @param defId Definition ID
     * @param msg   Custom error message
     */
    public PresentationDefinitionNotFoundException(final String defId,
                                                   final String msg) {

        super(DEFAULT_ERROR_CODE, msg);
        this.definitionId = defId;
    }

    /**
     * Get the definition ID that was not found.
     *
     * @return Definition ID
     */
    public String getDefinitionId() {
        return definitionId;
    }
}
