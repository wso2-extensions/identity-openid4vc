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

package org.wso2.carbon.identity.openid4vc.presentation.dto;

import com.google.gson.JsonElement;
import com.google.gson.annotations.SerializedName;

import java.util.List;

/**
 * Data Transfer Object for Presentation Definition API responses.
 * Contains comprehensive information about a presentation definition.
 */
public class PresentationDefinitionResponseDTO {

    @SerializedName("id")
    private String id;

    @SerializedName("definitionId")
    private String definitionId;

    @SerializedName("name")
    private String name;

    @SerializedName("purpose")
    private String purpose;

    @SerializedName("description")
    private String description;

    @SerializedName("input_descriptors")
    private List<InputDescriptorDTO> inputDescriptors;

    @SerializedName("format")
    private FormatDTO format;

    @SerializedName("submission_requirements")
    private List<SubmissionRequirementDTO> submissionRequirements;

    @SerializedName("definitionJson")
    private JsonElement definitionJson;

    @SerializedName("isDefault")
    private boolean isDefault;

    @SerializedName("createdAt")
    private Long createdAt;

    @SerializedName("updatedAt")
    private Long updatedAt;

    /**
     * Default constructor.
     */
    public PresentationDefinitionResponseDTO() {
    }

    // Getters and Setters

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getDefinitionId() {
        return definitionId;
    }

    public void setDefinitionId(String definitionId) {
        this.definitionId = definitionId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPurpose() {
        return purpose;
    }

    public void setPurpose(String purpose) {
        this.purpose = purpose;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<InputDescriptorDTO> getInputDescriptors() {
        return inputDescriptors;
    }

    public void setInputDescriptors(List<InputDescriptorDTO> inputDescriptors) {
        this.inputDescriptors = inputDescriptors;
    }

    public FormatDTO getFormat() {
        return format;
    }

    public void setFormat(FormatDTO format) {
        this.format = format;
    }

    public List<SubmissionRequirementDTO> getSubmissionRequirements() {
        return submissionRequirements;
    }

    public void setSubmissionRequirements(List<SubmissionRequirementDTO> submissionRequirements) {
        this.submissionRequirements = submissionRequirements;
    }

    public JsonElement getDefinitionJson() {
        return definitionJson;
    }

    public void setDefinitionJson(JsonElement definitionJson) {
        this.definitionJson = definitionJson;
    }

    public boolean isDefault() {
        return isDefault;
    }

    public void setDefault(boolean isDefault) {
        this.isDefault = isDefault;
    }

    public Long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Long createdAt) {
        this.createdAt = createdAt;
    }

    public Long getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Long updatedAt) {
        this.updatedAt = updatedAt;
    }

    /**
     * Input Descriptor DTO for presentation definition.
     */
    public static class InputDescriptorDTO {

        @SerializedName("id")
        private String id;

        @SerializedName("name")
        private String name;

        @SerializedName("purpose")
        private String purpose;

        @SerializedName("format")
        private FormatDTO format;

        @SerializedName("constraints")
        private ConstraintsDTO constraints;

        @SerializedName("group")
        private List<String> group;

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getPurpose() {
            return purpose;
        }

        public void setPurpose(String purpose) {
            this.purpose = purpose;
        }

        public FormatDTO getFormat() {
            return format;
        }

        public void setFormat(FormatDTO format) {
            this.format = format;
        }

        public ConstraintsDTO getConstraints() {
            return constraints;
        }

        public void setConstraints(ConstraintsDTO constraints) {
            this.constraints = constraints;
        }

        public List<String> getGroup() {
            return group;
        }

        public void setGroup(List<String> group) {
            this.group = group;
        }
    }

    /**
     * Format DTO for supported VC formats.
     */
    public static class FormatDTO {

        @SerializedName("ldp_vc")
        private FormatDetailDTO ldpVc;

        @SerializedName("ldp_vp")
        private FormatDetailDTO ldpVp;

        @SerializedName("jwt_vc")
        private FormatDetailDTO jwtVc;

        @SerializedName("jwt_vc_json")
        private FormatDetailDTO jwtVcJson;

        @SerializedName("jwt_vp")
        private FormatDetailDTO jwtVp;

        @SerializedName("jwt_vp_json")
        private FormatDetailDTO jwtVpJson;

        @SerializedName("vc+sd-jwt")
        private FormatDetailDTO vcSdJwt;

        public FormatDetailDTO getLdpVc() {
            return ldpVc;
        }

        public void setLdpVc(FormatDetailDTO ldpVc) {
            this.ldpVc = ldpVc;
        }

        public FormatDetailDTO getLdpVp() {
            return ldpVp;
        }

        public void setLdpVp(FormatDetailDTO ldpVp) {
            this.ldpVp = ldpVp;
        }

        public FormatDetailDTO getJwtVc() {
            return jwtVc;
        }

        public void setJwtVc(FormatDetailDTO jwtVc) {
            this.jwtVc = jwtVc;
        }

        public FormatDetailDTO getJwtVcJson() {
            return jwtVcJson;
        }

        public void setJwtVcJson(FormatDetailDTO jwtVcJson) {
            this.jwtVcJson = jwtVcJson;
        }

        public FormatDetailDTO getJwtVp() {
            return jwtVp;
        }

        public void setJwtVp(FormatDetailDTO jwtVp) {
            this.jwtVp = jwtVp;
        }

        public FormatDetailDTO getJwtVpJson() {
            return jwtVpJson;
        }

        public void setJwtVpJson(FormatDetailDTO jwtVpJson) {
            this.jwtVpJson = jwtVpJson;
        }

        public FormatDetailDTO getVcSdJwt() {
            return vcSdJwt;
        }

        public void setVcSdJwt(FormatDetailDTO vcSdJwt) {
            this.vcSdJwt = vcSdJwt;
        }
    }

    /**
     * Format detail DTO with proof types or algorithms.
     */
    public static class FormatDetailDTO {

        @SerializedName("proof_type")
        private List<String> proofType;

        @SerializedName("alg")
        private List<String> alg;

        public List<String> getProofType() {
            return proofType;
        }

        public void setProofType(List<String> proofType) {
            this.proofType = proofType;
        }

        public List<String> getAlg() {
            return alg;
        }

        public void setAlg(List<String> alg) {
            this.alg = alg;
        }
    }

    /**
     * Constraints DTO for input descriptor constraints.
     */
    public static class ConstraintsDTO {

        @SerializedName("fields")
        private List<FieldDTO> fields;

        @SerializedName("limit_disclosure")
        private String limitDisclosure;

        public List<FieldDTO> getFields() {
            return fields;
        }

        public void setFields(List<FieldDTO> fields) {
            this.fields = fields;
        }

        public String getLimitDisclosure() {
            return limitDisclosure;
        }

        public void setLimitDisclosure(String limitDisclosure) {
            this.limitDisclosure = limitDisclosure;
        }
    }

    /**
     * Field DTO for constraint fields.
     */
    public static class FieldDTO {

        @SerializedName("path")
        private List<String> path;

        @SerializedName("id")
        private String id;

        @SerializedName("purpose")
        private String purpose;

        @SerializedName("name")
        private String name;

        @SerializedName("filter")
        private FilterDTO filter;

        @SerializedName("optional")
        private Boolean optional;

        @SerializedName("predicate")
        private String predicate;

        public List<String> getPath() {
            return path;
        }

        public void setPath(List<String> path) {
            this.path = path;
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getPurpose() {
            return purpose;
        }

        public void setPurpose(String purpose) {
            this.purpose = purpose;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public FilterDTO getFilter() {
            return filter;
        }

        public void setFilter(FilterDTO filter) {
            this.filter = filter;
        }

        public Boolean getOptional() {
            return optional;
        }

        public void setOptional(Boolean optional) {
            this.optional = optional;
        }

        public String getPredicate() {
            return predicate;
        }

        public void setPredicate(String predicate) {
            this.predicate = predicate;
        }
    }

    /**
     * Filter DTO for field filtering.
     */
    public static class FilterDTO {

        @SerializedName("type")
        private String type;

        @SerializedName("pattern")
        private String pattern;

        @SerializedName("const")
        private Object constValue;

        @SerializedName("enum")
        private List<Object> enumValues;

        @SerializedName("minimum")
        private Number minimum;

        @SerializedName("maximum")
        private Number maximum;

        @SerializedName("exclusiveMinimum")
        private Number exclusiveMinimum;

        @SerializedName("exclusiveMaximum")
        private Number exclusiveMaximum;

        @SerializedName("minLength")
        private Integer minLength;

        @SerializedName("maxLength")
        private Integer maxLength;

        @SerializedName("format")
        private String format;

        @SerializedName("not")
        private FilterDTO not;

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getPattern() {
            return pattern;
        }

        public void setPattern(String pattern) {
            this.pattern = pattern;
        }

        public Object getConstValue() {
            return constValue;
        }

        public void setConstValue(Object constValue) {
            this.constValue = constValue;
        }

        public List<Object> getEnumValues() {
            return enumValues;
        }

        public void setEnumValues(List<Object> enumValues) {
            this.enumValues = enumValues;
        }

        public Number getMinimum() {
            return minimum;
        }

        public void setMinimum(Number minimum) {
            this.minimum = minimum;
        }

        public Number getMaximum() {
            return maximum;
        }

        public void setMaximum(Number maximum) {
            this.maximum = maximum;
        }

        public Number getExclusiveMinimum() {
            return exclusiveMinimum;
        }

        public void setExclusiveMinimum(Number exclusiveMinimum) {
            this.exclusiveMinimum = exclusiveMinimum;
        }

        public Number getExclusiveMaximum() {
            return exclusiveMaximum;
        }

        public void setExclusiveMaximum(Number exclusiveMaximum) {
            this.exclusiveMaximum = exclusiveMaximum;
        }

        public Integer getMinLength() {
            return minLength;
        }

        public void setMinLength(Integer minLength) {
            this.minLength = minLength;
        }

        public Integer getMaxLength() {
            return maxLength;
        }

        public void setMaxLength(Integer maxLength) {
            this.maxLength = maxLength;
        }

        public String getFormat() {
            return format;
        }

        public void setFormat(String format) {
            this.format = format;
        }

        public FilterDTO getNot() {
            return not;
        }

        public void setNot(FilterDTO not) {
            this.not = not;
        }
    }

    /**
     * Submission requirement DTO.
     */
    public static class SubmissionRequirementDTO {

        @SerializedName("name")
        private String name;

        @SerializedName("purpose")
        private String purpose;

        @SerializedName("rule")
        private String rule;

        @SerializedName("count")
        private Integer count;

        @SerializedName("min")
        private Integer min;

        @SerializedName("max")
        private Integer max;

        @SerializedName("from")
        private String from;

        @SerializedName("from_nested")
        private List<SubmissionRequirementDTO> fromNested;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getPurpose() {
            return purpose;
        }

        public void setPurpose(String purpose) {
            this.purpose = purpose;
        }

        public String getRule() {
            return rule;
        }

        public void setRule(String rule) {
            this.rule = rule;
        }

        public Integer getCount() {
            return count;
        }

        public void setCount(Integer count) {
            this.count = count;
        }

        public Integer getMin() {
            return min;
        }

        public void setMin(Integer min) {
            this.min = min;
        }

        public Integer getMax() {
            return max;
        }

        public void setMax(Integer max) {
            this.max = max;
        }

        public String getFrom() {
            return from;
        }

        public void setFrom(String from) {
            this.from = from;
        }

        public List<SubmissionRequirementDTO> getFromNested() {
            return fromNested;
        }

        public void setFromNested(List<SubmissionRequirementDTO> fromNested) {
            this.fromNested = fromNested;
        }
    }
}
