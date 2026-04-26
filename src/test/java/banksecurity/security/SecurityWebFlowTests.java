package banksecurity.security;

import banksecurity.model.User;
import banksecurity.SecureAccessMonitoringApplication;
import banksecurity.repository.SecurityLogRepository;
import banksecurity.repository.UserRepository;
import banksecurity.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = SecureAccessMonitoringApplication.class)
@AutoConfigureMockMvc
class SecurityWebFlowTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SecurityLogRepository securityLogRepository;

    @BeforeEach
    void clearData() {
        securityLogRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    void registrationEndpointShouldNotExposeSensitiveFields() throws Exception {
        mockMvc.perform(post("/users/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "anna",
                                  "password": "Secure123"
                                }
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("anna"))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.blocked").doesNotExist());
    }

    @Test
    void stateChangingEndpointsShouldRequireCsrfToken() throws Exception {
        mockMvc.perform(post("/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "anna",
                                  "password": "Secure123"
                                }
                                """))
                .andExpect(status().isForbidden());
    }

    @Test
    void publicPagesShouldSendSecurityHeaders() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'self'")))
                .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Referrer-Policy", "same-origin"))
                .andExpect(header().string("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"));
    }

    @Test
    void csrfEndpointShouldReturnTokenMetadata() throws Exception {
        mockMvc.perform(get("/csrf"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.parameterName").value("_csrf"))
                .andExpect(jsonPath("$.headerName").value(anyOf(equalTo("X-XSRF-TOKEN"), equalTo("X-CSRF-TOKEN"))))
                .andExpect(jsonPath("$.token").isNotEmpty());
    }

    @Test
    void unsupportedPublicMethodsShouldBeDenied() throws Exception {
        mockMvc.perform(get("/users/register"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void credentialConfirmationShouldRequireAuthentication() throws Exception {
        mockMvc.perform(post("/review/confirmation")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "password": "secret123"
                                }
                                """))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void credentialConfirmationShouldUseSignedInAccount() throws Exception {
        userService.register("anna", "Secure123", "USER");

        mockMvc.perform(post("/review/confirmation")
                        .with(csrf())
                        .with(user("anna").roles("USER"))
                        .contentType(MediaType.APPLICATION_JSON)
                .content("""
                                {
                                  "password": "Secure123"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("APPROVED"))
                .andExpect(jsonPath("$.message").value(startsWith("Password confirmed")));
    }

    @Test
    void credentialConfirmationShouldReturnForbiddenForBlockedSignedInAccount() throws Exception {
        userService.register("anna", "Secure123", "USER");
        User user = userRepository.findByUsername("anna").orElseThrow();
        user.setBlocked(true);
        userRepository.save(user);

        mockMvc.perform(post("/review/confirmation")
                        .with(csrf())
                        .with(user("anna").roles("USER"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "password": "Secure123"
                                }
                                """))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("Account is blocked"));
    }

    @Test
    void protectedActionShouldRequireAuthentication() throws Exception {
        userService.register("anna", "Secure123", "USER");

        mockMvc.perform(post("/review/action")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "actionType": "EXPORT_DATA"
                                }
                                """))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void currentUserEndpointShouldReturnSignedInAccount() throws Exception {
        userService.register("anna", "Secure123", "USER");

        mockMvc.perform(get("/users/me")
                        .with(user("anna").roles("USER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("anna"))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    void loginPageShouldServeCustomForm() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk());
    }

    @Test
    void formLoginShouldRedirectToHomeWhenCredentialsAreCorrect() throws Exception {
        userService.register("anna", "Secure123", "USER");

        mockMvc.perform(post("/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", "anna")
                        .param("password", "Secure123"))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", "/"));
    }

    @Test
    void failedFormLoginShouldEventuallyBlockTheAccount() throws Exception {
        userService.register("anna", "Secure123", "USER");

        for (int attempt = 0; attempt < 2; attempt++) {
            mockMvc.perform(post("/login")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .param("username", "anna")
                            .param("password", "wrongpass1"))
                    .andExpect(status().isFound())
                    .andExpect(header().string("Location", "/login?error"));
        }

        mockMvc.perform(post("/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", "anna")
                        .param("password", "wrongpass1"))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", "/login?blocked"));

        User savedUser = userRepository.findByUsername("anna").orElseThrow();
        org.assertj.core.api.Assertions.assertThat(savedUser.isBlocked()).isTrue();
    }

    @Test
    void blockedAccountShouldLoseAccessToLogs() throws Exception {
        userService.register("anna", "Secure123", "USER");
        User user = userRepository.findByUsername("anna").orElseThrow();
        user.setBlocked(true);
        userRepository.save(user);

        mockMvc.perform(get("/users/logs")
                        .with(user("anna").roles("USER")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("Account is blocked"));
    }
}
