package banksecurity.service;

import banksecurity.dto.ProtectedActionRequest;
import banksecurity.dto.RiskReviewResponse;
import banksecurity.exception.UserNotFoundException;
import banksecurity.model.ProtectedActionType;
import banksecurity.model.RiskLevel;
import banksecurity.model.SecurityEventType;
import banksecurity.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
public class ProtectedActionRiskService {

    private final UserRepository userRepository;
    private final SecurityLogService securityLogService;
    private final AccessContextService accessContextService;

    public ProtectedActionRiskService(UserRepository userRepository,
                                     SecurityLogService securityLogService,
                                     AccessContextService accessContextService) {
        this.userRepository = userRepository;
        this.securityLogService = securityLogService;
        this.accessContextService = accessContextService;
    }

    @Transactional
    public RiskReviewResponse reviewAction(String username,
                                          ProtectedActionRequest request,
                                          AccessContext context) {
        String normalizedUsername = requireText(username, "Username must not be blank");
        ProtectedActionType actionType = requireActionType(request.actionType());

        userRepository.findByUsername(normalizedUsername)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

        List<String> reasons = new ArrayList<>();
        int score = baseScoreForAction(actionType, reasons);
        score += applyContextSignals(context, reasons);
        RiskLevel riskLevel = mapScoreToRisk(score);

        String status = riskLevel == RiskLevel.HIGH ? "REVIEW_REQUIRED" : "APPROVED";
        String message = buildMessage(riskLevel);

        if (riskLevel != RiskLevel.HIGH) {
            accessContextService.rememberTrustedContext(normalizedUsername, context);
        }

        securityLogService.log(
                riskLevel == RiskLevel.HIGH ? SecurityEventType.PROTECTED_ACTION_FLAGGED : SecurityEventType.PROTECTED_ACTION_APPROVED,
                riskLevel,
                normalizedUsername,
                context.source(),
                "score=" + score
                        + ", actionType=" + actionType
                        + ", newDevice=" + context.newDevice()
                        + ", newSource=" + context.newSource()
                        + ", deviceId=" + context.deviceId()
        );

        return new RiskReviewResponse(status, riskLevel, message, reasons);
    }

    private int baseScoreForAction(ProtectedActionType actionType, List<String> reasons) {
        return switch (actionType) {
            case VIEW_ACTIVITY -> {
                reasons.add("Viewing account activity is treated as low risk");
                yield 0;
            }
            case UPDATE_PROFILE -> {
                reasons.add("Changing profile data adds a small amount of risk");
                yield 1;
            }
            case CHANGE_EMAIL, CHANGE_PASSWORD -> {
                reasons.add("Changing email or password is treated as a more sensitive step");
                yield 2;
            }
            case EXPORT_DATA -> {
                reasons.add("Exporting account data is treated as a sensitive action");
                yield 3;
            }
        };
    }

    private int applyContextSignals(AccessContext context, List<String> reasons) {
        int score = 0;

        if (context.newDevice()) {
            score += 2;
            reasons.add("This browser has not been seen for this account before");
        }

        if (context.newSource()) {
            score += 1;
            reasons.add("This source address is new for this account");
        }

        if (!context.newDevice() && !context.newSource()) {
            reasons.add("The request comes from a known browser and a known source");
        }

        return score;
    }

    private RiskLevel mapScoreToRisk(int score) {
        if (score >= 5) {
            return RiskLevel.HIGH;
        }
        if (score >= 2) {
            return RiskLevel.MEDIUM;
        }
        return RiskLevel.LOW;
    }

    private String requireText(String value, String message) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(message);
        }
        return value.trim();
    }

    private ProtectedActionType requireActionType(ProtectedActionType actionType) {
        if (actionType == null) {
            throw new IllegalArgumentException("Action type is required");
        }
        return actionType;
    }

    private String buildMessage(RiskLevel riskLevel) {
        return switch (riskLevel) {
            case LOW -> "Action approved";
            case MEDIUM -> "Action approved, but the session was marked for extra attention";
            case HIGH -> "Action held for review";
        };
    }
}
