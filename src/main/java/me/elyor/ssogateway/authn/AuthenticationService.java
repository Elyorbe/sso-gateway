package me.elyor.ssogateway.authn;

import me.elyor.ssogateway.authn.common.AuthenticationProvider;
import me.elyor.ssogateway.authn.oauth2.GoogleOAuth2UserInfo;
import me.elyor.ssogateway.authn.token.TokenService;
import me.elyor.ssogateway.user.User;
import org.springframework.data.mongodb.core.ReactiveMongoOperations;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.Map;

@Service
public class AuthenticationService {

    private static final String USER_COLLECTION = "users";

    private TokenService tokenService;
    private ReactiveMongoOperations mongoOps;


    public AuthenticationService(TokenService tokenService, ReactiveMongoOperations mongoOps) {
        this.tokenService = tokenService;
        this.mongoOps = mongoOps;
    }

    /**
     * Saves user info in mongo. Create access and refresh tokens.
     * Adds tokens to cookies
     * */
    public Mono<Void> onAuthenticationSuccess(ServerWebExchange exchange, Authentication authentication) {
        if (!(authentication instanceof OAuth2AuthenticationToken))
            return Mono.empty(); // We only have OAuth2.0 login at the moment.
        Mono<User> userMono = saveUser((OAuth2AuthenticationToken) authentication);
        return userMono.flatMap(user -> tokenService.createAccessToken(user.getEmail())
                .doOnNext(accessToken -> exchange.getResponse().addCookie(ResponseCookie
                        .from("accessToken", accessToken)
                        .build()))
                .flatMap(accessToken -> tokenService.createRefreshToken(user.getEmail())
                        .doOnNext(refreshToken -> exchange.getResponse().addCookie(ResponseCookie
                                .from("refreshToken", refreshToken)
                                .build()))
                        .then()));
    }

    private Mono<User> saveUser(OAuth2AuthenticationToken authentication) {
        DefaultOAuth2User oAuth2Principal = (DefaultOAuth2User) authentication.getPrincipal();
        User user = userFromAttributes(oAuth2Principal.getAttributes());
        return mongoOps.save(user, USER_COLLECTION);
    }

    private User userFromAttributes(Map<String, Object> attributes) {
        GoogleOAuth2UserInfo googleOAuth2UserInfo =
                new GoogleOAuth2UserInfo(attributes);
        return User.builder()
                .email(googleOAuth2UserInfo.getEmail())
                .name(googleOAuth2UserInfo.getName())
                .authProvider(AuthenticationProvider.GOOGLE)
                .oauth2Id(googleOAuth2UserInfo.getId())
                .isLocked(false)
                .isEnabled(true)
                .lastLoginAt(LocalDateTime.now())
                .build();
    }

}
