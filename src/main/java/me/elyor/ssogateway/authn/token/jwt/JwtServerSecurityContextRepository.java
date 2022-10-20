package me.elyor.ssogateway.authn.token.jwt;

import lombok.extern.slf4j.Slf4j;
import me.elyor.ssogateway.global.RuleConfigurer;
import me.elyor.ssogateway.global.error.ErrorResponse;
import me.elyor.ssogateway.global.error.exception.ErrorCode;
import me.elyor.ssogateway.global.error.exception.GlobalException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
public class JwtServerSecurityContextRepository implements ServerSecurityContextRepository {

    private JwtAuthenticationManager jwtAuthenticationManager;
    private RuleConfigurer ruleConfigurer;

    public JwtServerSecurityContextRepository(JwtAuthenticationManager jwtAuthenticationManager) {
        this.jwtAuthenticationManager = jwtAuthenticationManager;
        this.ruleConfigurer = new RuleConfigurer();
    }

    public void setRuleConfigurer(RuleConfigurer ruleConfigurer) {
        this.ruleConfigurer = ruleConfigurer;
    }

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        return Mono.empty();
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        return ruleConfigurer.isAllowed(exchange.getRequest().getPath())
                .flatMap(allowed -> {
                    if(allowed) // path doesn't require authorization header
                        return Mono.empty();
                    return securityContextFromJwt(exchange);
                });
    }

    private Mono<SecurityContext> securityContextFromJwt(ServerWebExchange exchange) {
        return resolveAccessToken(exchange.getRequest())
                .map(accessToken -> new JwtAuthenticationToken(accessToken, accessToken,
                        AuthorityUtils.NO_AUTHORITIES))
                .flatMap(jwtAuthenticationToken -> jwtAuthenticationManager
                        .authenticate(jwtAuthenticationToken)
                        .map(SecurityContextImpl::new));
    }

    private Mono<String> resolveAccessToken(ServerHttpRequest request) {
        String authzHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        String tokenType = "Bearer ";
        if(authzHeader != null && authzHeader.startsWith(tokenType))
            return Mono.just(authzHeader.substring(tokenType.length()));
        String reason = "Authorization header is not present or malformed";
        log.error(reason);
        List<ErrorResponse.FieldError> errors = ErrorResponse
                .FieldError.of("Header", "Authorization", reason);
        return Mono.error(new GlobalException(ErrorCode.BAD_REQUEST, errors));
    }

}
