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

package org.wso2.carbon.identity.openid4vc.template.management.util;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.ExpressionNode;
import org.wso2.carbon.identity.core.model.FilterTreeBuilder;
import org.wso2.carbon.identity.core.model.Node;
import org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants;
import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtClientException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.AFTER_GT;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.BEFORE_LT;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.CO;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.EQ;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.EW;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.ErrorMessages.ERROR_CODE_INVALID_FIELD;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.GE;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.GT;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.LE;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.LT;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.SW;

/**
 * Utility class for VC Template filter operations.
 */
public class VCTemplateFilterUtil {

    /**
     * Get expression nodes from filter string with after/before cursors.
     *
     * @param filter Filter expression.
     * @param after  After cursor.
     * @param before Before cursor.
     * @return List of expression nodes.
     * @throws VCTemplateMgtClientException If filter parsing fails.
     */
    public static List<ExpressionNode> getExpressionNodes(String filter, String after, String before)
            throws VCTemplateMgtClientException {

        String paginatedFilter = getPaginatedFilter(filter, after, before);
        return getExpressionNodes(paginatedFilter);
    }

    /**
     * Get expression nodes from filter string.
     *
     * @param filter Filter expression.
     * @return List of expression nodes.
     * @throws VCTemplateMgtClientException If filter parsing fails.
     */
    public static List<ExpressionNode> getExpressionNodes(String filter) throws VCTemplateMgtClientException {

        List<ExpressionNode> expressionNodes = new ArrayList<>();
        if (StringUtils.isBlank(filter)) {
            return expressionNodes;
        }

        try {
            FilterTreeBuilder filterTreeBuilder = new FilterTreeBuilder(filter);
            Node rootNode = filterTreeBuilder.buildTree();
            setExpressionNodeList(rootNode, expressionNodes);
        } catch (IOException | IdentityException e) {
            throw VCTemplateMgtExceptionHandler.handleClientException(ERROR_CODE_INVALID_FIELD,
                    "Invalid filter expression: " + filter);
        }
        return expressionNodes;
    }

    /**
     * Build filter query from expression nodes.
     *
     * @param expressionNodes List of expression nodes.
     * @return Filter query builder.
     * @throws VCTemplateMgtClientException If filter building fails.
     */
    public static VCTemplateFilterQueryBuilder getFilterQueryBuilder(List<ExpressionNode> expressionNodes)
            throws VCTemplateMgtClientException {

        int count = 1;
        StringBuilder filter = new StringBuilder();
        VCTemplateFilterQueryBuilder filterQueryBuilder = new VCTemplateFilterQueryBuilder();

        if (CollectionUtils.isEmpty(expressionNodes)) {
            filterQueryBuilder.setFilterQuery(StringUtils.EMPTY);
        } else {
            for (ExpressionNode expressionNode : expressionNodes) {
                String operation = expressionNode.getOperation();
                String value = expressionNode.getValue();
                String attributeValue = expressionNode.getAttributeValue();
                String attributeName = VCTemplateManagementConstants.ATTRIBUTE_COLUMN_MAP.get(attributeValue);

                if (attributeName == null) {
                    throw VCTemplateMgtExceptionHandler.handleClientException(ERROR_CODE_INVALID_FIELD,
                            "Unsupported filter attribute: " + attributeValue);
                }

                count = buildFilterBasedOnOperation(filterQueryBuilder, attributeName, value, operation, count, filter);
            }
            if (StringUtils.isBlank(filter.toString())) {
                filterQueryBuilder.setFilterQuery(StringUtils.EMPTY);
            } else {
                filterQueryBuilder.setFilterQuery(filter.toString());
            }
        }
        return filterQueryBuilder;
    }

    /**
     * Build paginated filter with after/before cursors.
     *
     * @param filter Filter expression.
     * @param after  After cursor.
     * @param before Before cursor.
     * @return Paginated filter expression.
     */
    private static String getPaginatedFilter(String filter, String after, String before) {

        String paginatedFilter = StringUtils.isNotBlank(filter) ? filter : StringUtils.EMPTY;

        if (StringUtils.isNotBlank(before)) {
            String decodedString = new String(Base64.getDecoder().decode(before), StandardCharsets.UTF_8);
            paginatedFilter += (StringUtils.isNotBlank(paginatedFilter) ? " and " : "") + BEFORE_LT + decodedString;
        } else if (StringUtils.isNotBlank(after)) {
            String decodedString = new String(Base64.getDecoder().decode(after), StandardCharsets.UTF_8);
            paginatedFilter += (StringUtils.isNotBlank(paginatedFilter) ? " and " : "") + AFTER_GT + decodedString;
        }
        return paginatedFilter;
    }

    /**
     * Build filter based on operation.
     *
     * @param filterQueryBuilder Filter query builder.
     * @param attributeName      Attribute name.
     * @param value              Attribute value.
     * @param operation          Filter operation.
     * @param count              Parameter count.
     * @param filter             Filter string builder.
     * @return Updated parameter count.
     * @throws VCTemplateMgtClientException If operation is unsupported.
     */
    private static int buildFilterBasedOnOperation(VCTemplateFilterQueryBuilder filterQueryBuilder,
                                                   String attributeName, String value, String operation,
                                                   int count, StringBuilder filter)
            throws VCTemplateMgtClientException {

        if (StringUtils.isNotBlank(attributeName) && StringUtils.isNotBlank(value) &&
                StringUtils.isNotBlank(operation)) {
            switch (operation) {
                case EQ:
                    equalFilterBuilder(count, value, attributeName, filter, filterQueryBuilder);
                    ++count;
                    break;
                case SW:
                    startWithFilterBuilder(count, value, attributeName, filter, filterQueryBuilder);
                    ++count;
                    break;
                case EW:
                    endWithFilterBuilder(count, value, attributeName, filter, filterQueryBuilder);
                    ++count;
                    break;
                case CO:
                    containsFilterBuilder(count, value, attributeName, filter, filterQueryBuilder);
                    ++count;
                    break;
                case GE:
                    greaterThanOrEqualFilterBuilder(count, value, attributeName, filter, filterQueryBuilder);
                    ++count;
                    break;
                case LE:
                    lessThanOrEqualFilterBuilder(count, value, attributeName, filter, filterQueryBuilder);
                    ++count;
                    break;
                case GT:
                    greaterThanFilterBuilder(count, value, attributeName, filter, filterQueryBuilder);
                    ++count;
                    break;
                case LT:
                    lessThanFilterBuilder(count, value, attributeName, filter, filterQueryBuilder);
                    ++count;
                    break;
                default:
                    throw VCTemplateMgtExceptionHandler.handleClientException(ERROR_CODE_INVALID_FIELD,
                            "Unsupported filter operation: " + operation);
            }
        }
        return count;
    }

    /**
     * Build equal filter.
     */
    private static void equalFilterBuilder(int count, String value, String attributeName, StringBuilder filter,
                                           VCTemplateFilterQueryBuilder filterQueryBuilder) {

        filter.append(attributeName).append(" = ? AND ");
        filterQueryBuilder.setFilterAttributeValue(count, value);
    }

    /**
     * Build starts with filter.
     */
    private static void startWithFilterBuilder(int count, String value, String attributeName, StringBuilder filter,
                                               VCTemplateFilterQueryBuilder filterQueryBuilder) {

        filter.append(attributeName).append(" LIKE ? AND ");
        filterQueryBuilder.setFilterAttributeValue(count, value + "%");
    }

    /**
     * Build ends with filter.
     */
    private static void endWithFilterBuilder(int count, String value, String attributeName, StringBuilder filter,
                                            VCTemplateFilterQueryBuilder filterQueryBuilder) {

        filter.append(attributeName).append(" LIKE ? AND ");
        filterQueryBuilder.setFilterAttributeValue(count, "%" + value);
    }

    /**
     * Build contains filter.
     */
    private static void containsFilterBuilder(int count, String value, String attributeName, StringBuilder filter,
                                             VCTemplateFilterQueryBuilder filterQueryBuilder) {

        filter.append(attributeName).append(" LIKE ? AND ");
        filterQueryBuilder.setFilterAttributeValue(count, "%" + value + "%");
    }

    /**
     * Build greater than or equal filter.
     */
    private static void greaterThanOrEqualFilterBuilder(int count, String value, String attributeName,
                                                       StringBuilder filter,
                                                       VCTemplateFilterQueryBuilder filterQueryBuilder) {

        filter.append(attributeName).append(" >= ? AND ");
        filterQueryBuilder.setFilterAttributeValue(count, value);
    }

    /**
     * Build less than or equal filter.
     */
    private static void lessThanOrEqualFilterBuilder(int count, String value, String attributeName,
                                                    StringBuilder filter,
                                                    VCTemplateFilterQueryBuilder filterQueryBuilder) {

        filter.append(attributeName).append(" <= ? AND ");
        filterQueryBuilder.setFilterAttributeValue(count, value);
    }

    /**
     * Build greater than filter.
     */
    private static void greaterThanFilterBuilder(int count, String value, String attributeName, StringBuilder filter,
                                                VCTemplateFilterQueryBuilder filterQueryBuilder) {

        filter.append(attributeName).append(" > ? AND ");
        filterQueryBuilder.setFilterAttributeValue(count, value);
    }

    /**
     * Build less than filter.
     */
    private static void lessThanFilterBuilder(int count, String value, String attributeName, StringBuilder filter,
                                             VCTemplateFilterQueryBuilder filterQueryBuilder) {

        filter.append(attributeName).append(" < ? AND ");
        filterQueryBuilder.setFilterAttributeValue(count, value);
    }

    /**
     * Set expression node list from filter tree.
     *
     * @param node            Filter tree node.
     * @param expressionNodes Expression nodes list.
     */
    private static void setExpressionNodeList(Node node, List<ExpressionNode> expressionNodes) {

        if (node instanceof ExpressionNode) {
            expressionNodes.add((ExpressionNode) node);
        } else if (node.getLeftNode() != null) {
            setExpressionNodeList(node.getLeftNode(), expressionNodes);
        }
        if (node.getRightNode() != null) {
            setExpressionNodeList(node.getRightNode(), expressionNodes);
        }
    }
}
