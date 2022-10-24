package me.elyor.ssogateway.authn.token;

import com.nimbusds.jwt.JWTClaimsSet;
import me.elyor.ssogateway.authn.token.common.AccessToken;
import me.elyor.ssogateway.authn.token.common.RefreshToken;
import me.elyor.ssogateway.authn.token.store.MongoTokenStore;
import me.elyor.ssogateway.authn.token.store.RedisTokenStore;
import me.elyor.ssogateway.global.error.exception.GlobalException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Date;
import java.util.UUID;

import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
class TokenServiceTests {

    @Mock
    MongoTokenStore mongoTokenStore;

    @Mock
    RedisTokenStore redisTokenStore;

    TokenService tokenService;

    String jwtSecret = "1e605609-eaf7-421d-aeda-930c7e6cb913";
    String principal = "elyor@elyor.me";

    @BeforeEach
    void setup() throws Exception {
        tokenService = new TokenService(jwtSecret, mongoTokenStore, redisTokenStore);
        tokenService.afterPropertiesSet();
    }

    @Nested
    class AccessTokenTests {

        @BeforeEach
        void setup() {
            given(mongoTokenStore.storeAccessToken(Mockito.any(AccessToken.class)))
                    .willReturn(Mono.empty().then());
        }

        @Test
        void givenPrincipalThenCreateAccessToken() {
            Mono<String> accessToken = tokenService.createAccessToken(principal);
            StepVerifier.create(accessToken)
                    .assertNext(Assertions::assertNotNull)
                    .expectComplete()
                    .verify();
        }

        @Test
        void givenAccessTokenThenValidate() {
            Mono<String> accessToken = tokenService.createAccessToken(principal);
            Mono<JWTClaimsSet> jwtClaimsSet = accessToken.flatMap(a -> tokenService.validateAccessToken(a));
            StepVerifier.create(jwtClaimsSet)
                    .assertNext(Assertions::assertNotNull)
                    .expectComplete()
                    .verify();
        }

        @Test
        void givenInvalidAccessTokenThenError() {
            Mono<String> accessToken = tokenService.createAccessToken(principal);
            Mono<String> changedAccessToken = accessToken.map(String::toLowerCase);
            Mono<JWTClaimsSet> jwtClaimsSet = changedAccessToken.flatMap(a -> tokenService.validateAccessToken(a));
            StepVerifier.create(jwtClaimsSet)
                    .expectError(GlobalException.class)
                    .verify();
        }
    }


    @Test
    void givenPrincipalThenCreateRefreshToken() {
        given(mongoTokenStore.storeRefreshToken(Mockito.any(RefreshToken.class)))
                .willReturn(Mono.empty().then());
        given(redisTokenStore.storeRefreshToken(Mockito.any(RefreshToken.class)))
                .willReturn(Mono.empty().then());
        given(redisTokenStore.findRefreshToken(Mockito.any(String.class)))
                .willReturn(Mono.empty());
        Mono<String> refreshToken = tokenService.createRefreshToken(principal);
        StepVerifier.create(refreshToken)
                .assertNext(Assertions::assertNotNull)
                .expectComplete()
                .verify();
    }

    @Test
    void givenPrincipalAndRefreshTokenValueThenRefreshAccessToken() {
        given(mongoTokenStore.storeAccessToken(Mockito.any(AccessToken.class)))
                .willReturn(Mono.empty().then());
        RefreshToken refreshToken = createRefreshToken();
        given(redisTokenStore.findRefreshToken(Mockito.any(String.class)))
                .willReturn(Mono.just(refreshToken));
        Mono<String> accessToken = tokenService.refreshAccessToken(principal, refreshToken.getValue());
        StepVerifier.create(accessToken)
                .assertNext(Assertions::assertNotNull)
                .expectComplete()
                .verify();
    }

    private RefreshToken createRefreshToken() {
        String value = UUID.randomUUID().toString();
        Date issuedAt = new Date();
        Date expiresAt = new Date(issuedAt.getTime() + 60_000 * 60 * 24);
        return new RefreshToken(value, principal, issuedAt, expiresAt);
    }

}
