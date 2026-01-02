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

package org.wso2.carbon.identity.openid4vc.template.management;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.openid4vc.template.management.dao.PresentationTemplateDAO;
import org.wso2.carbon.identity.openid4vc.template.management.dao.impl.PresentationTemplateDAOImpl;
import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtException;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationTemplate;

import java.util.List;

/**
 * Implementation of PresentationTemplateService with caching support.
 */
public class PresentationTemplateServiceImpl implements PresentationTemplateService {

    private static final Log log = LogFactory.getLog(PresentationTemplateServiceImpl.class);
    private final PresentationTemplateDAO dao = new PresentationTemplateDAOImpl();

    // Default template JSON for OpenID4VP
    private static final String DEFAULT_TEMPLATE_JSON = "{\n" +
            "  \"client_id_prefix\": \"redirect_uri:\",\n" +
            "  \"accepted_formats\": [\"jwt_vc_json\", \"dc+sd-jwt\"],\n" +
            "  \"response_mode\": \"direct_post\",\n" +
            "  \"dcql\": {\n" +
            "    \"credentials\": [\n" +
            "      {\n" +
            "        \"id\": \"identity_credential\",\n" +
            "        \"format\": \"jwt_vc_json\",\n" +
            "        \"claims_path_pointers\": [\n" +
            "          {\"path\": \"$.vc.credentialSubject.email\"}\n" +
            "        ]\n" +
            "      }\n" +
            "    ]\n" +
            "  },\n" +
            "  \"metadata\": {\n" +
            "    \"nonce_required\": true\n" +
            "  }\n" +
            "}";

    @Override
    public PresentationTemplate createTemplate(PresentationTemplate template, String tenantDomain)
            throws VCTemplateMgtException {

        int tenantId = getTenantId(tenantDomain);

        // Validate template JSON
        if (template.getTemplateJson() == null || template.getTemplateJson().trim().isEmpty()) {
            throw new VCTemplateMgtException("Template JSON cannot be empty");
        }

        template.setTenantDomain(tenantDomain);
        return dao.createTemplate(template, tenantId);
    }

    @Override
    public PresentationTemplate getTemplateByClientId(String clientId, String version, String tenantDomain)
            throws VCTemplateMgtException {

        int tenantId = getTenantId(tenantDomain);
        return dao.getTemplateByClientId(clientId, version, tenantId);
    }

    @Override
    public PresentationTemplate updateTemplate(PresentationTemplate template, String tenantDomain)
            throws VCTemplateMgtException {

        int tenantId = getTenantId(tenantDomain);

        // Validate template JSON
        if (template.getTemplateJson() == null || template.getTemplateJson().trim().isEmpty()) {
            throw new VCTemplateMgtException("Template JSON cannot be empty");
        }

        template.setTenantDomain(tenantDomain);
        return dao.updateTemplate(template, tenantId);
    }

    @Override
    public void deleteTemplate(String clientId, String version, String tenantDomain)
            throws VCTemplateMgtException {

        int tenantId = getTenantId(tenantDomain);
        dao.deleteTemplate(clientId, version, tenantId);
    }

    @Override
    public List<PresentationTemplate> listTemplates(String tenantDomain) throws VCTemplateMgtException {

        int tenantId = getTenantId(tenantDomain);
        return dao.listTemplates(tenantId);
    }

    @Override
    public PresentationTemplate getOrCreateDefaultTemplate(String clientId, String tenantDomain)
            throws VCTemplateMgtException {

        int tenantId = getTenantId(tenantDomain);

        // Try to get existing template
        PresentationTemplate template = dao.getTemplateByClientId(clientId, "current", tenantId);

        if (template != null) {
            return template;
        }

        // Create default template
        if (log.isDebugEnabled()) {
            log.debug("Creating default presentation template for client: " + clientId);
        }

        template = new PresentationTemplate();
        template.setClientId(clientId);
        template.setVersion("current");
        template.setTemplateJson(DEFAULT_TEMPLATE_JSON);
        template.setPublic(true);
        template.setStatus("active");
        template.setTenantDomain(tenantDomain);

        return dao.createTemplate(template, tenantId);
    }

    private int getTenantId(String tenantDomain) {
        try {
            return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        } catch (Exception e) {
            log.warn("Failed to get tenant ID from context, using default tenant", e);
            return -1234; // Default tenant
        }
    }
}

