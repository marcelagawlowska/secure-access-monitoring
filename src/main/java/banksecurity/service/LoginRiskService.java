package banksecurity.service;

import banksecurity.dto.LoginAttemptRequest;
import banksecurity.dto.RiskReviewResponse;
import banksecurity.exception.UserNotFoundException;
import banksecurity.model.RiskLevel;
import banksecurity.model.SecurityEventType;
import banksecurity.model.User;
import banksecurity.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class LoginRiskService {

    private static final int MAX_FAILED_ATTEMPTS = 3;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecurityLogService securityLogService;
    private final AccessContextService accessContextService;

    public LoginRiskService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            SecurityLogService securityLogService,
            AccessContextService accessContextService
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.securityLogService = securityLogService;
        this.accessContextService = accessContextService;
    }

    @Transactional
    public RiskReviewResponse evaluateLoginAttempt(String username,
                                                   LoginAttemptRequest request,
                                                   AccessContext context) {
        String normalizedUsername = requireText(username, "Username must not be blank");
        String password = requireText(request.password(), "Password must not be blank");
        String normalizedSource = defaultSource(context.source());

        User user = userRepository.findByUsername(normalizedUsername)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + normalizedUsername));

        if (user.isBlocked()) {
            securityLogService.log(
                    SecurityEventType.USER_BLOCKED,
                    RiskLevel.HIGH,
                    user.getUsername(),
                    normalizedSource,
                    "Blocked account attempted to authenticate"
            );
            return blockedResponse();
        }

        if (!passwordEncoder.matches(password, user.getPassword())) {
            return handleFailedAttempt(user, context);
        }

        user.setFailedAttempts(0);
        userRepository.save(user);
        accessContextService.rememberTrustedContext(user.getUsername(), context);

        RiskLevel riskLevel = (context.newDevice() || context.newSource()) ? RiskLevel.MEDIUM : RiskLevel.LOW;
        String message = riskLevel == RiskLevel.MEDIUM
                ? "Password confirmed, but the session looks different than before"
                : "Password confirmed";
        List<String> reasons = successfulReasons(context);

        securityLogService.log(
                SecurityEventType.LOGIN_SUCCESS,
                riskLevel,
                user.getUsername(),
                normalizedSource,
                "Successful credential confirmation"
        );
        return new RiskReviewResponse(
                "APPROVED",
                riskLevel,
                message,
                reasons
        );
    }

    @Transactional
    public void recordSuccessfulAuthentication(String username, AccessContext context) {
        User user = userRepository.findByUsername(requireText(username, "Username must not be blank"))
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

        user.setFailedAttempts(0);
        userRepository.save(user);
        accessContextService.rememberTrustedContext(user.getUsername(), context);

        RiskLevel riskLevel = (context.newDevice() || context.newSource()) ? RiskLevel.MEDIUM : RiskLevel.LOW;
        securityLogService.log(
                SecurityEventType.LOGIN_SUCCESS,
                riskLevel,
                user.getUsername(),
                context.source(),
                "Interactive sign-in completed successfully"
        );
    }

    @Transactional
    public AuthenticationFailureResult recordFailedAuthentication(String username, String source) {
        if (username == null || username.isBlank()) {
            return new AuthenticationFailureResult(false, false);
        }

        User user = userRepository.findByUsername(username.trim()).orElse(null);
        if (user == null) {
            return new AuthenticationFailureResult(false, false);
        }

        if (user.isBlocked()) {
            securityLogService.log(
                    SecurityEventType.USER_BLOCKED,
                    RiskLevel.HIGH,
                    user.getUsername(),
                    defaultSource(source),
                    "Blocked account attempted interactive sign-in"
            );
            return new AuthenticationFailureResult(true, true);
        }

        boolean blocked = applyFailedAttempt(user, defaultSource(source));
        return new AuthenticationFailureResult(true, blocked);
    }

    private RiskReviewResponse handleFailedAttempt(User user, AccessContext context) {
        boolean blocked = applyFailedAttempt(user, defaultSource(context.source()));

        RiskLevel riskLevel = blocked ? RiskLevel.HIGH : RiskLevel.MEDIUM;
        List<String> reasons = new java.util.ArrayList<>();
        reasons.add(blocked
                ? "The wrong password was entered several times"
                : "The password did not match the account");
        reasons.add(blocked
                ? "The lockout limit was reached"
                : "Failed attempts counter increased to " + user.getFailedAttempts());
        if (context.newDevice()) {
            reasons.add("This browser has not been seen for this account before");
        }
        if (context.newSource()) {
            reasons.add("This source address is new for this account");
        }

        return new RiskReviewResponse(
                blocked ? "BLOCKED" : "DENIED",
                riskLevel,
                blocked ? "Account blocked after repeated failed checks" : "Password rejected",
                reasons
        );
    }

    private boolean applyFailedAttempt(User user, String source) {
        int failedAttempts = user.getFailedAttempts() + 1;
        user.setFailedAttempts(failedAttempts);

        boolean accountShouldBeBlocked = failedAttempts >= MAX_FAILED_ATTEMPTS;
        RiskLevel riskLevel = accountShouldBeBlocked ? RiskLevel.HIGH : RiskLevel.MEDIUM;

        if (accountShouldBeBlocked) {
            user.setBlocked(true);
            securityLogService.log(
                    SecurityEventType.USER_BLOCKED,
                    RiskLevel.HIGH,
                    user.getUsername(),
                    source,
                    "Account locked after repeated invalid credentials"
            );
        }

        userRepository.save(user);
        securityLogService.log(
                SecurityEventType.LOGIN_FAILED,
                riskLevel,
                user.getUsername(),
                source,
                "Failed login attempt #" + failedAttempts
        );
        return accountShouldBeBlocked;
    }

    private RiskReviewResponse blockedResponse() {
        return new RiskReviewResponse(
                "BLOCKED",
                RiskLevel.HIGH,
                "Account blocked after repeated failed checks",
                List.of("Account is already locked")
        );
    }

    private String requireText(String value, String message) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(message);
        }
        return value.trim();
    }

    private String defaultSource(String source) {
        return (source == null || source.isBlank()) ? "unknown" : source.trim();
    }

    private List<String> successfulReasons(AccessContext context) {
        if (context.newDevice() || context.newSource()) {
            List<String> reasons = new java.util.ArrayList<>();
            reasons.add("The password matched");
            if (context.newDevice()) {
                reasons.add("This browser was not known for this account");
            }
            if (context.newSource()) {
                reasons.add("This source address was not known for this account");
            }
            return reasons;
        }

        return List.of("The password matched", "The browser and source were already known");
    }
}
