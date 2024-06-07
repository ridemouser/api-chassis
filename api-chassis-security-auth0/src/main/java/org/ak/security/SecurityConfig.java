package org.ak.security;

import groovy.util.logging.Slf4j;
import org.ak.exception.RestAuthenticationFailureHandler;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.io.IOException;
import java.util.Arrays;

import static org.springframework.security.config.Customizer.withDefaults;

@Slf4j
@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    Logger logger = LogManager.getLogger(SecurityConfig.class);
    @Value("${okta.oauth2.issuer}")
    private String issuer;
    @Value("${okta.oauth2.client-id}")
    private String clientId;

    private final ClientRegistrationRepository clientRegistrationRepository;

    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    private final RestAuthenticationFailureHandler restAuthenticationFailureHandler;

    public SecurityConfig(ClientRegistrationRepository clientRegistrationRepository, CustomAuthenticationEntryPoint customAuthenticationEntryPoint, RestAuthenticationFailureHandler restAuthenticationFailureHandler) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.customAuthenticationEntryPoint = customAuthenticationEntryPoint;
        this.restAuthenticationFailureHandler = restAuthenticationFailureHandler;
    }
    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(this.clientRegistrationRepository, "/oauth2/authorization");
        authorizationRequestResolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());

        http.authorizeHttpRequests(authorize ->
                authorize.requestMatchers("/", "/images/**").permitAll()
                        .requestMatchers("/api/public/**").permitAll()
                        .requestMatchers("/api/internal/**").denyAll()
                        .requestMatchers("/api/internal-scoped/read/**").hasAuthority("SCOPE_read:securities")
                        .requestMatchers("/api/internal-scoped/write/**").hasAuthority("SCOPE_write:securities")
                        .anyRequest().denyAll())
                .cors(customizer ->
                        customizer.configurationSource(corsConfigurationSource()))
                .oauth2Login(oauth2-> oauth2.authorizationEndpoint(
                                authorization -> authorization
                                        .authorizationRequestResolver(authorizationRequestResolver))
                        .failureHandler(restAuthenticationFailureHandler))
                .oauth2ResourceServer(oauth2ResourceServer
                        -> oauth2ResourceServer.jwt(withDefaults())
                        .authenticationEntryPoint(customAuthenticationEntryPoint))
                .exceptionHandling(Customizer.withDefaults())
                .logout(logout -> logout.addLogoutHandler(logoutHandler()));

        logger.log(Level.INFO, "Entered Security config");
        return http.build();
    }

    private LogoutSuccessHandler logoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler logoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(this.clientRegistrationRepository);
        logoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");

        return logoutSuccessHandler;
    }
    private CorsConfigurationSource corsConfigurationSource() {
        final var configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("*"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setExposedHeaders(Arrays.asList("*"));

        final var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    private LogoutHandler logoutHandler() {
        return (request, response, authentication) -> {
            try {
                String baseUrl = ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString();
                response.sendRedirect(issuer + "v2/logout?client_id=" + clientId + "&returnTo=" + baseUrl);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        };
    }
}