package org.wso2.carbon.identity.openid4vc.template.management.internal;

import org.wso2.carbon.identity.api.resource.mgt.APIResourceManager;

/**
 * Data holder for VC Config Management Service.
 */
public class VCTemplateManagementServiceDataHolder {

    private APIResourceManager apiResourceManager;

    public static final VCTemplateManagementServiceDataHolder INSTANCE = new VCTemplateManagementServiceDataHolder();

    private VCTemplateManagementServiceDataHolder() {

    }

    /**
     * Get the instance of VCConfigManagementServiceDataHolder.
     *
     * @return VCConfigManagementServiceDataHolder instance.
     */
    public static VCTemplateManagementServiceDataHolder getInstance() {

        return INSTANCE;
    }

    public APIResourceManager getAPIResourceManager() {

        return apiResourceManager;
    }

    public void setAPIResourceManager(APIResourceManager apiResourceManager) {

        this.apiResourceManager = apiResourceManager;
    }
}
