package me.elyor.ssogateway.global.config;

import me.elyor.ssogateway.authn.AuthenticationEntryPoint;
import me.elyor.ssogateway.authn.oauth2.handler.AuthenticationSuccessHandler;
import me.elyor.ssogateway.authn.token.jwt.JwtAuthenticationManager;
import me.elyor.ssogateway.authn.token.jwt.JwtServerSecurityContextRepository;
import me.elyor.ssogateway.global.RuleConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.logout.HttpStatusReturningServerLogoutSuccessHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class SecurityConfig {

    private final static String[] WHITE_LIST = { "/actuator/**", "/api/v1/authn/token/refresh",
            "/oauth2/authorization/{registrationId}" };

    private AppProperties appProperties;
    private ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver;
    private AuthenticationSuccessHandler authenticationSuccessHandler;
    private JwtAuthenticationManager jwtAuthenticationManager;

    public SecurityConfig(AppProperties appProperties, AuthenticationSuccessHandler authenticationSuccessHandler,
                          ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver,
                          JwtAuthenticationManager jwtAuthenticationManager) {
        this.appProperties = appProperties;
        this.authorizationRequestResolver = authorizationRequestResolver;
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.jwtAuthenticationManager = jwtAuthenticationManager;
    }

    @Bean
    SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange().pathMatchers(WHITE_LIST).permitAll()
                .anyExchange().authenticated()
                .and()
                .oauth2Login(oauth2 -> oauth2
                        .authenticationSuccessHandler(authenticationSuccessHandler)
                        .authorizationRequestResolver(authorizationRequestResolver)
                        .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                )
                .logout()
                .logoutSuccessHandler(new HttpStatusReturningServerLogoutSuccessHandler())
                .and()
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(new AuthenticationEntryPoint()))
                .cors(cors -> cors
                        .configurationSource(corsConfigurationSource()))
                .csrf().disable()
                .securityContextRepository(securityContextRepository())
                .requestCache().requestCache(NoOpServerRequestCache.getInstance());

        return http.build();
    }

    private ServerSecurityContextRepository securityContextRepository() {
        var repository = new JwtServerSecurityContextRepository(jwtAuthenticationManager);
        RuleConfigurer configuration = new RuleConfigurer();
        configuration.pathMatchers(WHITE_LIST).permitAll();
        repository.setRuleConfigurer(configuration);
        return repository;
    }

    private CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(appProperties.cors().allowedOrigins());
        configuration.setAllowedMethods(appProperties.cors().allowedMethods());
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}
