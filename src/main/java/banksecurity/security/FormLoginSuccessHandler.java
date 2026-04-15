package banksecurity.security;

import banksecurity.service.AccessContext;
import banksecurity.service.AccessContextService;
import banksecurity.service.LoginRiskService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class FormLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final AccessContextService accessContextService;
    private final LoginRiskService loginRiskService;

    public FormLoginSuccessHandler(AccessContextService accessContextService,
                                   LoginRiskService loginRiskService) {
        this.accessContextService = accessContextService;
        this.loginRiskService = loginRiskService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        AccessContext context = accessContextService.resolve(authentication.getName(), request, response);
        loginRiskService.recordSuccessfulAuthentication(authentication.getName(), context);
        response.sendRedirect("/");
    }
}
