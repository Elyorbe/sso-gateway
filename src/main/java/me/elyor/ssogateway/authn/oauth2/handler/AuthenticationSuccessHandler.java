package me.elyor.ssogateway.authn.oauth2.handler;

import me.elyor.ssogateway.authn.AuthenticationService;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

@Component
public class AuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {

    private ServerRedirectStrategy redirectStrategy;
    private AuthenticationService authenticationService;

    public AuthenticationSuccessHandler(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
        redirectStrategy = new DefaultServerRedirectStrategy();
    }

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        ServerWebExchange exchange = webFilterExchange.getExchange();
        return authenticationService.onAuthenticationSuccess(exchange, authentication)
                .then(redirectStrategy
                        .sendRedirect(exchange,
                                resolveRedirectUri(exchange.getRequest())
                        ));
    }

    private URI resolveRedirectUri(ServerHttpRequest httpRequest) {
        String encodedUrlSafeState = httpRequest.getQueryParams().getFirst("state");
        if (!StringUtils.hasText(encodedUrlSafeState))
            return URI.create(httpRequest.getURI().getHost());
        byte[] redirectUriByte = Base64Utils.decodeFromUrlSafeString(encodedUrlSafeState);
        return URI.create(new String(redirectUriByte));
    }

}
