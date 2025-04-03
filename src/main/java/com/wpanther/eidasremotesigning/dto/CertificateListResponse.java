package com.wpanther.eidasremotesigning.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateListResponse {
    private List<CertificateSummary> certificates;
    private int total;
}
