package banksecurity.service;

import banksecurity.exception.DuplicateUsernameException;
import banksecurity.exception.AccountBlockedException;
import banksecurity.exception.UserNotFoundException;
import banksecurity.model.RiskLevel;
import banksecurity.model.SecurityEventType;
import banksecurity.model.User;
import banksecurity.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.regex.Pattern;

@Service
public class UserService {

    private static final Pattern USERNAME_PATTERN = Pattern.compile("[A-Za-z0-9._-]{3,30}");
    private static final Pattern PASSWORD_DIGIT_PATTERN = Pattern.compile(".*\\d.*");
    private static final Pattern PASSWORD_LETTER_PATTERN = Pattern.compile(".*[A-Za-z].*");

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecurityLogService securityLogService;

    public UserService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            SecurityLogService securityLogService
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.securityLogService = securityLogService;
    }

    @Transactional
    public User register(String username, String password, String role) {
        String normalizedUsername = normalizeUsername(username);
        String normalizedRole = normalizeRole(role);
        validatePassword(password);

        userRepository.findByUsername(normalizedUsername).ifPresent(existingUser -> {
            throw new DuplicateUsernameException("Username already exists: " + normalizedUsername);
        });

        User user = new User();
        user.setUsername(normalizedUsername);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(normalizedRole);
        user.setBlocked(false);
        user.setFailedAttempts(0);

        User savedUser = userRepository.saveAndFlush(user);
        securityLogService.log(
                SecurityEventType.USER_REGISTERED,
                RiskLevel.LOW,
                savedUser.getUsername(),
                "account-registration",
                "New user registered with role " + normalizedRole
        );
        return savedUser;
    }

    @Transactional(readOnly = true)
    public void ensureActiveUser(String username) {
        getActiveUser(username);
    }

    @Transactional(readOnly = true)
    public User getActiveUser(String username) {
        User user = userRepository.findByUsername(normalizeUsername(username))
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

        if (user.isBlocked()) {
            throw new AccountBlockedException("Account is blocked");
        }

        return user;
    }

    private String normalizeUsername(String username) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username must not be blank");
        }

        String normalizedUsername = username.trim();
        if (!USERNAME_PATTERN.matcher(normalizedUsername).matches()) {
            throw new IllegalArgumentException("Username must be 3-30 characters long and use only letters, numbers, dots, dashes or underscores");
        }

        return normalizedUsername;
    }

    private void validatePassword(String password) {
        if (password == null || password.isBlank()) {
            throw new IllegalArgumentException("Password must not be blank");
        }

        String normalizedPassword = password.trim();
        if (normalizedPassword.length() < 8) {
            throw new IllegalArgumentException("Password must contain at least 8 characters");
        }

        if (!PASSWORD_LETTER_PATTERN.matcher(normalizedPassword).matches()
                || !PASSWORD_DIGIT_PATTERN.matcher(normalizedPassword).matches()) {
            throw new IllegalArgumentException("Password must include at least one letter and one number");
        }
    }

    private String normalizeRole(String role) {
        if (role == null || role.isBlank()) {
            throw new IllegalArgumentException("Role must not be blank");
        }
        return role.trim().toUpperCase();
    }
}
