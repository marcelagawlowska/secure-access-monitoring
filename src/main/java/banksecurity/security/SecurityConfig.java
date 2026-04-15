package banksecurity.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           BlockedAccountFilter blockedAccountFilter,
                                           FormLoginSuccessHandler formLoginSuccessHandler,
                                           FormLoginFailureHandler formLoginFailureHandler) throws Exception {
        RequestMatcher apiRequestMatcher = new OrRequestMatcher(
                new AntPathRequestMatcher("/review/**"),
                new AntPathRequestMatcher("/users/logs"),
                new AntPathRequestMatcher("/users/me"),
                new AntPathRequestMatcher("/csrf")
        );

        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/index.html").permitAll()
                        .requestMatchers("/login.html").permitAll()
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/csrf").permitAll()
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/users/register").permitAll()
                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers("/review/confirmation").authenticated()
                        .requestMatchers("/review/action").authenticated()
                        .requestMatchers("/users/me").authenticated()
                        .requestMatchers("/users/logs").authenticated()
                        .anyRequest().denyAll()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(formLoginSuccessHandler)
                        .failureHandler(formLoginFailureHandler)
                )
                .logout(logout -> logout.logoutSuccessUrl("/").permitAll())
                .httpBasic(AbstractHttpConfigurer::disable)
                .addFilterAfter(blockedAccountFilter, SecurityContextHolderFilter.class)
                .exceptionHandling(exception -> exception
                        .defaultAuthenticationEntryPointFor(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                apiRequestMatcher
                        )
                        .accessDeniedHandler((request, response, accessDeniedException) ->
                                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied"))
                );

        return http.build();
    }
}
