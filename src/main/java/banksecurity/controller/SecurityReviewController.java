package banksecurity.controller;

import banksecurity.dto.LoginAttemptRequest;
import banksecurity.dto.ProtectedActionRequest;
import banksecurity.dto.RiskReviewResponse;
import banksecurity.service.AccessContext;
import banksecurity.service.AccessContextService;
import banksecurity.service.LoginRiskService;
import banksecurity.service.ProtectedActionRiskService;
import banksecurity.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/review")
public class SecurityReviewController {

    private final LoginRiskService loginRiskService;
    private final ProtectedActionRiskService protectedActionRiskService;
    private final UserService userService;
    private final AccessContextService accessContextService;

    public SecurityReviewController(LoginRiskService loginRiskService,
                                    ProtectedActionRiskService protectedActionRiskService,
                                    UserService userService,
                                    AccessContextService accessContextService) {
        this.loginRiskService = loginRiskService;
        this.protectedActionRiskService = protectedActionRiskService;
        this.userService = userService;
        this.accessContextService = accessContextService;
    }

    @PostMapping("/confirmation")
    public ResponseEntity<RiskReviewResponse> confirmCredentials(@RequestBody LoginAttemptRequest request,
                                                                 Authentication authentication,
                                                                 HttpServletRequest servletRequest,
                                                                 HttpServletResponse servletResponse) {
        String currentUsername = requireCurrentUser(authentication);
        userService.ensureActiveUser(currentUsername);
        AccessContext context = accessContextService.resolve(currentUsername, servletRequest, servletResponse);
        return ResponseEntity.ok(loginRiskService.evaluateLoginAttempt(
                currentUsername,
                request,
                context
        ));
    }

    @PostMapping("/action")
    public ResponseEntity<RiskReviewResponse> reviewProtectedAction(@RequestBody ProtectedActionRequest request,
                                                                    Authentication authentication,
                                                                    HttpServletRequest servletRequest,
                                                                    HttpServletResponse servletResponse) {
        String currentUsername = requireCurrentUser(authentication);
        userService.ensureActiveUser(currentUsername);
        AccessContext context = accessContextService.resolve(currentUsername, servletRequest, servletResponse);
        return ResponseEntity.ok(protectedActionRiskService.reviewAction(currentUsername, request, context));
    }

    private String requireCurrentUser(Authentication authentication) {
        if (authentication == null || authentication.getName() == null) {
            throw new IllegalArgumentException("Sign in first to continue");
        }
        return authentication.getName();
    }
}
