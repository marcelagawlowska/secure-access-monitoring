package banksecurity.security;

import banksecurity.service.AccessContextService;
import banksecurity.service.AuthenticationFailureResult;
import banksecurity.service.LoginRiskService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class FormLoginFailureHandler implements AuthenticationFailureHandler {

    private final LoginRiskService loginRiskService;
    private final AccessContextService accessContextService;

    public FormLoginFailureHandler(LoginRiskService loginRiskService,
                                   AccessContextService accessContextService) {
        this.loginRiskService = loginRiskService;
        this.accessContextService = accessContextService;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        String username = request.getParameter("username");
        String source = accessContextService.resolveSource(request);
        AuthenticationFailureResult result = loginRiskService.recordFailedAuthentication(username, source);

        if (result.blocked()) {
            response.sendRedirect("/login?blocked");
            return;
        }

        response.sendRedirect("/login?error");
    }
}
