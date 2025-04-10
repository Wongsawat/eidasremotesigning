package com.wpanther.eidasremotesigning.dto.csc;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;



import java.util.Map;

/**
 * CSC API signature attributes
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SignatureAttributes {
    private String signatureType;
    private String signatureLevel;
    private String signatureForm;
    private Long signDate;
    private String signaturePolicyId;
    private Map<String, Object> commitmentTypeIndications;
    private Map<String, Object> otherSignatureAttributes;
}
