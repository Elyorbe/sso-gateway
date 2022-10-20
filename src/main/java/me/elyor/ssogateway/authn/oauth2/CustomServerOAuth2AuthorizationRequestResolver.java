package me.elyor.ssogateway.authn.oauth2;

import org.springframework.http.server.PathContainer;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.Base64Utils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import java.util.Optional;
import java.util.function.Consumer;

/**
 * Responsible for customizing OAuth2.0 authorization request.
 * Such as adding state parameter
 * */
public class CustomServerOAuth2AuthorizationRequestResolver
        extends DefaultServerOAuth2AuthorizationRequestResolver {

    private final ServerWebExchangeMatcher authorizationRequestMatcher;
    private PathPatternParser pathPatternParser;

    public CustomServerOAuth2AuthorizationRequestResolver(
            ReactiveClientRegistrationRepository clientRegistrationRepository) {
        super(clientRegistrationRepository);
        this.authorizationRequestMatcher =
                new PathPatternParserServerWebExchangeMatcher(DEFAULT_AUTHORIZATION_REQUEST_PATTERN);
        this.pathPatternParser = new PathPatternParser();
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange) {
        checkLoginAttempt(exchange);
        return this.authorizationRequestMatcher
                .matches(exchange)
                .filter(ServerWebExchangeMatcher.MatchResult::isMatch)
                .map(ServerWebExchangeMatcher.MatchResult::getVariables)
                .map((variables) -> variables.get(DEFAULT_REGISTRATION_ID_URI_VARIABLE_NAME))
                .cast(String.class)
                .flatMap((clientRegistrationId) -> resolve(exchange, clientRegistrationId));
    }

    private void checkLoginAttempt(ServerWebExchange exchange) {
        PathContainer currentPath = exchange.getRequest().getPath().pathWithinApplication();
        PathPattern defaultAuthzRequestPattern = pathPatternParser.parse(DEFAULT_AUTHORIZATION_REQUEST_PATTERN);
        if(defaultAuthzRequestPattern.matches(currentPath)) {
            setCustomParameters(exchange);
        }
    }

    /**
     * {@code state} parameter is used for redirecting after successful login.
     * This parameter optional. The value will be used for redirection
     * if a client calls OAuth2 login endpoint. If not present,
     * redirection will be made to requesting host.
     * <p>
     *     Google login example:
     * </p>
     * {@code https://example.com/oauth2/authorization/google?state=https://elyor.me }
     *
     * Request will be redirected https://elyor.me on successful login.
     * If not present, it will be redirected to https://example.com
     * */
    private void setCustomParameters(ServerWebExchange exchange) {
        exchange.getRequest().getURI();
        String state = Optional.ofNullable(exchange.getRequest()
                .getQueryParams().getFirst("state"))
                .orElse(exchange.getRequest().getURI().getHost());
        setAuthorizationRequestCustomizer(authorizationRequestCustomizer
                (Base64Utils.encodeToUrlSafeString(state.getBytes())));
    }

    private Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer(String state) {
        return customizer -> customizer
                .additionalParameters(params -> params.put("access_type", "offline"))
                .state(state);
    }

}
