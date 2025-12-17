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

package org.wso2.carbon.identity.openid4vc.issuance.offer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.issuance.common.util.CommonUtil;
import org.wso2.carbon.identity.openid4vc.issuance.offer.exception.CredentialOfferException;
import org.wso2.carbon.identity.openid4vc.issuance.offer.internal.CredentialOfferDataHolder;
import org.wso2.carbon.identity.openid4vc.issuance.offer.response.CredentialOfferResponse;
import org.wso2.carbon.identity.openid4vc.issuance.offer.util.CredentialOfferExceptionHandler;
import org.wso2.carbon.identity.openid4vc.template.management.VCTemplateManager;
import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtException;
import org.wso2.carbon.identity.openid4vc.template.management.model.VCTemplate;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.openid4vc.issuance.offer.constant.CredentialOfferConstants.ErrorMessages.ERROR_CODE_INVALID_OFFER_ID;
import static org.wso2.carbon.identity.openid4vc.issuance.offer.constant.CredentialOfferConstants.ErrorMessages.ERROR_CODE_RETRIEVAL_ERROR;
import static org.wso2.carbon.identity.openid4vc.issuance.offer.constant.CredentialOfferConstants.ErrorMessages.ERROR_CODE_URL_BUILD_ERROR;


/**
 * Default implementation for credential offer processing.
 */
public class DefaultCredentialOfferProcessor implements CredentialOfferProcessor {

    private static final Log LOG = LogFactory.getLog(DefaultCredentialOfferProcessor.class);
    private static final DefaultCredentialOfferProcessor defaultCredentialOfferProcessor =
            new DefaultCredentialOfferProcessor();

    private DefaultCredentialOfferProcessor() {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Initializing DefaultCredentialOfferProcessor for CredentialOfferProcessor.");
        }
    }

    public static DefaultCredentialOfferProcessor getInstance() {

        return defaultCredentialOfferProcessor;
    }

    @Override
    public CredentialOfferResponse generateOffer(String offerId, String tenantDomain)
            throws CredentialOfferException {

        try {
            Map<String, Object> offer = new LinkedHashMap<>();

            // Set credential issuer URL
            offer.put(Constants.CredentialOffer.CREDENTIAL_ISSUER, buildCredentialIssuerUrl(tenantDomain));

            String identifier = getCredentialConfigurationIdentifier(offerId,
                    tenantDomain);

            List<String> credentialConfigIds = new ArrayList<>();
            credentialConfigIds.add(identifier);

            offer.put(Constants.CredentialOffer.CREDENTIAL_CONFIGURATION_IDS, credentialConfigIds);

            Map<String, Object> grants = new LinkedHashMap<>();
            Map<String, Object> authCodeGrant = new LinkedHashMap<>();

            authCodeGrant.put(Constants.CredentialOffer.AUTHORIZATION_SERVER,
                    buildAuthorizationServerUrl(tenantDomain));

            grants.put(Constants.CredentialOffer.AUTHORIZATION_CODE, authCodeGrant);
            offer.put(Constants.CredentialOffer.GRANTS, grants);

            return new CredentialOfferResponse(offer);
        } catch (URLBuilderException e) {
            throw CredentialOfferExceptionHandler.handleServerException(ERROR_CODE_URL_BUILD_ERROR, e);
        }
    }

    private static String getCredentialConfigurationIdentifier(String offerId, String tenantDomain)
            throws CredentialOfferException {

        VCTemplateManager vcTemplateManager = CredentialOfferDataHolder.getInstance()
                .getVcCredentialConfigManager();
        try {
            VCTemplate config  = vcTemplateManager.getByOfferId(offerId, tenantDomain);
            if (config == null) {
                throw CredentialOfferExceptionHandler.handleClientException(ERROR_CODE_INVALID_OFFER_ID, offerId);
            }
            return config.getIdentifier();
        } catch (VCTemplateMgtException e) {
            throw CredentialOfferExceptionHandler.handleServerException(ERROR_CODE_RETRIEVAL_ERROR, e, offerId);
        }
    }

    private String buildCredentialIssuerUrl(String tenantDomain) throws URLBuilderException {

        return CommonUtil.buildServiceUrl(tenantDomain, Constants.CONTEXT_OPENID4VCI).getAbsolutePublicURL();
    }

    private String buildAuthorizationServerUrl(String tenantDomain) throws URLBuilderException {

        return CommonUtil.buildServiceUrl(tenantDomain, Constants.SEGMENT_OAUTH2, Constants.SEGMENT_TOKEN)
                .getAbsolutePublicURL();
    }
}

