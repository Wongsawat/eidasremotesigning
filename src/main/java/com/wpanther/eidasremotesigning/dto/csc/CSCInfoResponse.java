package com.wpanther.eidasremotesigning.dto.csc;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * CSC API info response
 * Based on CSC API v2.0 specifications
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CSCInfoResponse {
    private String name;
    private String logo;
    private String region;
    private List<String> lang;
    private String description;
    private Map<String, Object> authType;
    private List<String> methods;
    private List<String> timeStampPolicies;

    /**
     * Indicates whether the service supports asynchronous operation mode
     * CSC API v2.0 specification field
     */
    private Boolean asynchronousOperationMode;
}
