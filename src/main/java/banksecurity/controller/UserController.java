package banksecurity.controller;

import banksecurity.dto.CurrentUserResponse;
import banksecurity.dto.RegisteredUserResponse;
import banksecurity.dto.RegistrationRequest;
import banksecurity.dto.SecurityLogResponse;
import banksecurity.model.SecurityLog;
import banksecurity.model.User;
import banksecurity.service.SecurityLogService;
import banksecurity.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;
    private final SecurityLogService securityLogService;

    public UserController(UserService userService, SecurityLogService securityLogService) {
        this.userService = userService;
        this.securityLogService = securityLogService;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisteredUserResponse> register(@RequestBody RegistrationRequest request) {
        User user = userService.register(request.username(), request.password(), "USER");
        RegisteredUserResponse response = new RegisteredUserResponse(user.getId(), user.getUsername(), user.getRole());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/logs")
    public ResponseEntity<List<SecurityLogResponse>> logs(Authentication authentication) {
        userService.ensureActiveUser(authentication.getName());
        return ResponseEntity.ok(toResponses(securityLogService.getLogsForUser(authentication.getName())));
    }

    @GetMapping("/me")
    public ResponseEntity<CurrentUserResponse> currentUser(Authentication authentication) {
        User user = userService.getActiveUser(authentication.getName());
        return ResponseEntity.ok(new CurrentUserResponse(user.getUsername(), user.getRole()));
    }

    private List<SecurityLogResponse> toResponses(List<SecurityLog> logs) {
        return logs.stream()
                .map(SecurityLogResponse::from)
                .toList();
    }
}
