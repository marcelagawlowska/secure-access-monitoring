package banksecurity.dto;

import banksecurity.model.SecurityLog;

import java.time.LocalDateTime;

public record SecurityLogResponse(
        Long id,
        String eventType,
        String riskLevel,
        String username,
        String source,
        String details,
        LocalDateTime createdAt
) {
    public static SecurityLogResponse from(SecurityLog log) {
        return new SecurityLogResponse(
                log.getId(),
                log.getEventType() != null ? log.getEventType().name() : null,
                log.getRiskLevel() != null ? log.getRiskLevel().name() : null,
                log.getUsername(),
                log.getSource(),
                log.getDetails(),
                log.getCreatedAt()
        );
    }
}
