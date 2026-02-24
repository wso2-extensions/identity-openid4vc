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

package org.wso2.carbon.identity.openid4vc.presentation.common.dto;

import com.google.gson.JsonElement;
import com.google.gson.annotations.SerializedName;

import java.util.ArrayList;
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
        if (inputDescriptors == null) {
            return null;
        }
        return new ArrayList<>(inputDescriptors);
    }

    public void setInputDescriptors(List<InputDescriptorDTO> inputDescriptors) {
        if (inputDescriptors == null) {
            this.inputDescriptors = null;
        } else {
            this.inputDescriptors = new ArrayList<>(inputDescriptors);
        }
    }

    public FormatDTO getFormat() {
        return format != null ? new FormatDTO(format) : null;
    }

    public void setFormat(FormatDTO format) {
        this.format = format != null ? new FormatDTO(format) : null;
    }

    public List<SubmissionRequirementDTO> getSubmissionRequirements() {
        if (submissionRequirements == null) {
            return null;
        }
        return new ArrayList<>(submissionRequirements);
    }

    public void setSubmissionRequirements(List<SubmissionRequirementDTO> submissionRequirements) {
        if (submissionRequirements == null) {
            this.submissionRequirements = null;
        } else {
            this.submissionRequirements = new ArrayList<>(submissionRequirements);
        }
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

        public InputDescriptorDTO() {
        }

        public InputDescriptorDTO(InputDescriptorDTO other) {
            this.id = other.id;
            this.name = other.name;
            this.purpose = other.purpose;
            this.format = other.format != null ? new FormatDTO(other.format) : null;
            this.constraints = other.constraints != null ? new ConstraintsDTO(other.constraints) : null;
            this.group = other.group != null ? new ArrayList<>(other.group) : null;
        }

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
            return format != null ? new FormatDTO(format) : null;
        }

        public void setFormat(FormatDTO format) {
            this.format = format != null ? new FormatDTO(format) : null;
        }

        public ConstraintsDTO getConstraints() {
            return constraints != null ? new ConstraintsDTO(constraints) : null;
        }

        public void setConstraints(ConstraintsDTO constraints) {
            this.constraints = constraints != null ? new ConstraintsDTO(constraints) : null;
        }

        public List<String> getGroup() {
            if (group == null) {
                return null;
            }
            return new ArrayList<>(group);
        }

        public void setGroup(List<String> group) {
            this.group = group != null ? new ArrayList<>(group) : null;
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

        public FormatDTO() {
        }

        public FormatDTO(FormatDTO other) {
            this.ldpVc = other.ldpVc != null ? new FormatDetailDTO(other.ldpVc) : null;
            this.ldpVp = other.ldpVp != null ? new FormatDetailDTO(other.ldpVp) : null;
            this.jwtVc = other.jwtVc != null ? new FormatDetailDTO(other.jwtVc) : null;
            this.jwtVcJson = other.jwtVcJson != null ? new FormatDetailDTO(other.jwtVcJson) : null;
            this.jwtVp = other.jwtVp != null ? new FormatDetailDTO(other.jwtVp) : null;
            this.jwtVpJson = other.jwtVpJson != null ? new FormatDetailDTO(other.jwtVpJson) : null;
            this.vcSdJwt = other.vcSdJwt != null ? new FormatDetailDTO(other.vcSdJwt) : null;
        }

        public FormatDetailDTO getLdpVc() {
            return ldpVc != null ? new FormatDetailDTO(ldpVc) : null;
        }

        public void setLdpVc(FormatDetailDTO ldpVc) {
            this.ldpVc = ldpVc != null ? new FormatDetailDTO(ldpVc) : null;
        }

        public FormatDetailDTO getLdpVp() {
            return ldpVp != null ? new FormatDetailDTO(ldpVp) : null;
        }

        public void setLdpVp(FormatDetailDTO ldpVp) {
            this.ldpVp = ldpVp != null ? new FormatDetailDTO(ldpVp) : null;
        }

        public FormatDetailDTO getJwtVc() {
            return jwtVc != null ? new FormatDetailDTO(jwtVc) : null;
        }

        public void setJwtVc(FormatDetailDTO jwtVc) {
            this.jwtVc = jwtVc != null ? new FormatDetailDTO(jwtVc) : null;
        }

        public FormatDetailDTO getJwtVcJson() {
            return jwtVcJson != null ? new FormatDetailDTO(jwtVcJson) : null;
        }

        public void setJwtVcJson(FormatDetailDTO jwtVcJson) {
            this.jwtVcJson = jwtVcJson != null ? new FormatDetailDTO(jwtVcJson) : null;
        }

        public FormatDetailDTO getJwtVp() {
            return jwtVp != null ? new FormatDetailDTO(jwtVp) : null;
        }

        public void setJwtVp(FormatDetailDTO jwtVp) {
            this.jwtVp = jwtVp != null ? new FormatDetailDTO(jwtVp) : null;
        }

        public FormatDetailDTO getJwtVpJson() {
            return jwtVpJson != null ? new FormatDetailDTO(jwtVpJson) : null;
        }

        public void setJwtVpJson(FormatDetailDTO jwtVpJson) {
            this.jwtVpJson = jwtVpJson != null ? new FormatDetailDTO(jwtVpJson) : null;
        }

        public FormatDetailDTO getVcSdJwt() {
            return vcSdJwt != null ? new FormatDetailDTO(vcSdJwt) : null;
        }

        public void setVcSdJwt(FormatDetailDTO vcSdJwt) {
            this.vcSdJwt = vcSdJwt != null ? new FormatDetailDTO(vcSdJwt) : null;
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

        public FormatDetailDTO() {
        }

        public FormatDetailDTO(FormatDetailDTO other) {
            this.proofType = other.proofType != null ? new ArrayList<>(other.proofType) : null;
            this.alg = other.alg != null ? new ArrayList<>(other.alg) : null;
        }

        public List<String> getProofType() {
            if (proofType == null) {
                return null;
            }
            return new ArrayList<>(proofType);
        }

        public void setProofType(List<String> proofType) {
            this.proofType = proofType != null ? new ArrayList<>(proofType) : null;
        }

        public List<String> getAlg() {
            if (alg == null) {
                return null;
            }
            return new ArrayList<>(alg);
        }

        public void setAlg(List<String> alg) {
            this.alg = alg != null ? new ArrayList<>(alg) : null;
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

        public ConstraintsDTO() {
        }

        public ConstraintsDTO(ConstraintsDTO other) {
            this.fields = other.fields != null ? new ArrayList<>(other.fields) : null; // Note: Shallow list copy, but
                                                                                       // FieldDTO (if mutable) might
                                                                                       // need deep copy logic if list

            // Actually, if FieldDTO is mutable, we should probably deep copy the list.
            if (other.fields != null) {
                this.fields = new ArrayList<>();
                for (FieldDTO field : other.fields) {
                    this.fields.add(new FieldDTO(field));
                }
            }
            this.limitDisclosure = other.limitDisclosure;
        }

        public List<FieldDTO> getFields() {
            if (fields == null) {
                return null;
            }
            return new ArrayList<>(fields); // This is shallow copy of list. SpotBugs usually accepts this for List
                                            // fields.
        }

        public void setFields(List<FieldDTO> fields) {
            this.fields = fields != null ? new ArrayList<>(fields) : null;
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

        public FieldDTO() {
        }

        public FieldDTO(FieldDTO other) {
            this.path = other.path != null ? new ArrayList<>(other.path) : null;
            this.id = other.id;
            this.purpose = other.purpose;
            this.name = other.name;
            this.filter = other.filter != null ? new FilterDTO(other.filter) : null;
            this.optional = other.optional;
            this.predicate = other.predicate;
        }

        public List<String> getPath() {
            if (path == null) {
                return null;
            }
            return new ArrayList<>(path);
        }

        public void setPath(List<String> path) {
            this.path = path != null ? new ArrayList<>(path) : null;
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
            return filter != null ? new FilterDTO(filter) : null;
        }

        public void setFilter(FilterDTO filter) {
            this.filter = filter != null ? new FilterDTO(filter) : null;
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

        public FilterDTO() {
        }

        public FilterDTO(FilterDTO other) {
            this.type = other.type;
            this.pattern = other.pattern;
            this.constValue = other.constValue; // Object, assumed immutable or acceptable
            this.enumValues = other.enumValues != null ? new ArrayList<>(other.enumValues) : null;
            this.minimum = other.minimum;
            this.maximum = other.maximum;
            this.exclusiveMinimum = other.exclusiveMinimum;
            this.exclusiveMaximum = other.exclusiveMaximum;
            this.minLength = other.minLength;
            this.maxLength = other.maxLength;
            this.format = other.format;
            this.not = other.not != null ? new FilterDTO(other.not) : null;
        }

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
            if (enumValues == null) {
                return null;
            }
            return new ArrayList<>(enumValues);
        }

        public void setEnumValues(List<Object> enumValues) {
            this.enumValues = enumValues != null ? new ArrayList<>(enumValues) : null;
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
            return not != null ? new FilterDTO(not) : null;
        }

        public void setNot(FilterDTO not) {
            this.not = not != null ? new FilterDTO(not) : null;
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

        public SubmissionRequirementDTO() {
        }

        public SubmissionRequirementDTO(SubmissionRequirementDTO other) {
            this.name = other.name;
            this.purpose = other.purpose;
            this.rule = other.rule;
            this.count = other.count;
            this.min = other.min;
            this.max = other.max;
            this.from = other.from;
            if (other.fromNested != null) {
                this.fromNested = new ArrayList<>();
                for (SubmissionRequirementDTO nested : other.fromNested) {
                    this.fromNested.add(new SubmissionRequirementDTO(nested));
                }
            }
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
            if (fromNested == null) {
                return null;
            }
            return new ArrayList<>(fromNested);
        }

        public void setFromNested(List<SubmissionRequirementDTO> fromNested) {
            this.fromNested = fromNested != null ? new ArrayList<>(fromNested) : null;
        }
    }
}
