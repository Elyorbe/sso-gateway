package me.elyor.ssogateway.authn.token.jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import me.elyor.ssogateway.authn.token.TokenService;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationManager implements ReactiveAuthenticationManager {

    private TokenService tokenService;

    public JwtAuthenticationManager(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) throws AuthenticationException {
        return tokenService.validateAccessToken((String)authentication.getCredentials())
                .map(this::authenticationFromClaims);
    }

    private Authentication authenticationFromClaims(JWTClaimsSet claimsSet) {
        var principal = new JwtAuthenticatedPrincipal(claimsSet.getSubject());
        var authentication = new JwtAuthenticationToken(principal, AuthorityUtils.NO_AUTHORITIES);
        authentication.setAuthenticated(true);
        return authentication;
    }

}
