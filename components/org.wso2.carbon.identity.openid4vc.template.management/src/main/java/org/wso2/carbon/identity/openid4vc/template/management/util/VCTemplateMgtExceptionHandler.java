/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.template.management.util;

import org.apache.commons.lang.ArrayUtils;
import org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants;
import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtClientException;
import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtServerException;

/**
 * Utility class for VC Template Management exception handling.
 */
public class VCTemplateMgtExceptionHandler {

    private VCTemplateMgtExceptionHandler() {
    }

    /**
     * Handle VC Template Management client exceptions.
     *
     * @param error Error message.
     * @param data  Data.
     * @return VCTemplateMgtClientException.
     */
    public static VCTemplateMgtClientException handleClientException(
            VCTemplateManagementConstants.ErrorMessages error, Object... data) {

        String description = error.getDescription();
        if (ArrayUtils.isNotEmpty(data)) {
            description = String.format(description, data);
        }

        return new VCTemplateMgtClientException(error.getMessage(), description, error.getCode());
    }

    /**
     * Handle VC Template Management server exceptions.
     *
     * @param error Error message.
     * @param e     Throwable.
     * @param data  Data.
     * @return VCTemplateMgtServerException.
     */
    public static VCTemplateMgtServerException handleServerException(
            VCTemplateManagementConstants.ErrorMessages error, Throwable e, Object... data) {

        String description = error.getDescription();
        if (ArrayUtils.isNotEmpty(data)) {
            description = String.format(description, data);
        }

        return new VCTemplateMgtServerException(error.getMessage(), description, error.getCode(), e);
    }
}
