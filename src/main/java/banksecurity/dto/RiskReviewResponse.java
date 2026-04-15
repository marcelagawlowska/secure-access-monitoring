package banksecurity.dto;

import banksecurity.model.RiskLevel;

import java.util.List;

public record RiskReviewResponse(
        String status,
        RiskLevel riskLevel,
        String message,
        List<String> reasons
) {
}
