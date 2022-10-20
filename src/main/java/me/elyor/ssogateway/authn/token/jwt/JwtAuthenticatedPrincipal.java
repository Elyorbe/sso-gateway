package me.elyor.ssogateway.authn.token.jwt;

import org.springframework.security.core.AuthenticatedPrincipal;

public class JwtAuthenticatedPrincipal implements AuthenticatedPrincipal {

    private String name;

    public JwtAuthenticatedPrincipal(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

}
