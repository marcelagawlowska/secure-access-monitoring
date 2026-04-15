package banksecurity.service;

import banksecurity.dto.LoginAttemptRequest;
import banksecurity.dto.ProtectedActionRequest;
import banksecurity.dto.RiskReviewResponse;
import banksecurity.SecureAccessMonitoringApplication;
import banksecurity.exception.DuplicateUsernameException;
import banksecurity.model.ProtectedActionType;
import banksecurity.model.RiskLevel;
import banksecurity.model.User;
import banksecurity.repository.SecurityLogRepository;
import banksecurity.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest(classes = SecureAccessMonitoringApplication.class)
class SecurityWorkflowTests {

    @Autowired
    private UserService userService;

    @Autowired
    private LoginRiskService loginRiskService;

    @Autowired
    private ProtectedActionRiskService protectedActionRiskService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SecurityLogRepository securityLogRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void clearData() {
        securityLogRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    void registerShouldHashPasswordAndRejectDuplicateUsername() {
        User user = userService.register("anna", "Secure123", "USER");

        assertThat(user.getPassword()).isNotEqualTo("Secure123");
        assertThat(passwordEncoder.matches("Secure123", user.getPassword())).isTrue();

        assertThatThrownBy(() -> userService.register("anna", "another123", "USER"))
                .isInstanceOf(DuplicateUsernameException.class);
    }

    @Test
    void loginShouldBlockAccountAfterThreeFailedAttempts() {
        userService.register("anna", "Secure123", "USER");

        loginRiskService.evaluateLoginAttempt(
                "anna",
                new LoginAttemptRequest("wrong-1"),
                new AccessContext("10.0.0.1", "device-a", false, false)
        );
        loginRiskService.evaluateLoginAttempt(
                "anna",
                new LoginAttemptRequest("wrong-2"),
                new AccessContext("10.0.0.1", "device-a", false, false)
        );
        RiskReviewResponse result = loginRiskService.evaluateLoginAttempt(
                "anna",
                new LoginAttemptRequest("wrong-3"),
                new AccessContext("10.0.0.1", "device-a", false, false)
        );

        User savedUser = userRepository.findByUsername("anna").orElseThrow();

        assertThat(result.status()).isEqualTo("BLOCKED");
        assertThat(result.riskLevel()).isEqualTo(RiskLevel.HIGH);
        assertThat(savedUser.isBlocked()).isTrue();
        assertThat(savedUser.getFailedAttempts()).isEqualTo(3);
    }

    @Test
    void protectedActionShouldRequireReviewWhenRiskIsHigh() {
        userService.register("anna", "Secure123", "USER");

        RiskReviewResponse result = protectedActionRiskService.reviewAction(
                "anna",
                new ProtectedActionRequest(ProtectedActionType.EXPORT_DATA),
                new AccessContext("10.0.0.1", "device-b", true, false)
        );

        assertThat(result.status()).isEqualTo("REVIEW_REQUIRED");
        assertThat(result.riskLevel()).isEqualTo(RiskLevel.HIGH);
        assertThat(result.reasons()).isNotEmpty();
    }

    @Test
    void registerShouldRejectVeryWeakPassword() {
        assertThatThrownBy(() -> userService.register("anna", "1234", "USER"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Password must contain at least 8 characters");
    }
}
