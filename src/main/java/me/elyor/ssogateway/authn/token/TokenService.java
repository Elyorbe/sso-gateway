package me.elyor.ssogateway.authn.token;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.openid.connect.sdk.validators.BadJWTExceptions;
import lombok.extern.slf4j.Slf4j;
import me.elyor.ssogateway.authn.token.common.AccessToken;
import me.elyor.ssogateway.authn.token.common.RefreshToken;
import me.elyor.ssogateway.authn.token.store.MongoTokenStore;
import me.elyor.ssogateway.authn.token.store.RedisTokenStore;
import me.elyor.ssogateway.global.error.ErrorResponse;
import me.elyor.ssogateway.global.error.exception.ErrorCode;
import me.elyor.ssogateway.global.error.exception.GlobalException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Slf4j
@Component
@SuppressWarnings("FieldCanBeLocal")
public class TokenService implements InitializingBean {

    private int accessTokenValidityMilliSeconds =  60_000 * 15; // default 15 minutes.
    private int refreshTokenValidityMilliSeconds = 60_000 * 60 * 24; // default 1 day.
    private JWSSigner signer;
    private String secret;
    private JWSVerifier signatureVerifier;
    private JOSEObjectType type = JOSEObjectType.JWT;
    private JOSEObjectTypeVerifier<SecurityContext> typeVerifier =
            new DefaultJOSEObjectTypeVerifier<>(type);
    private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;

    private MongoTokenStore mongoTokenStore;
    private RedisTokenStore redisTokenStore;

    public TokenService(@Value("${app.security.jwt.secret}") String secret, MongoTokenStore mongoTokenStore,
                        RedisTokenStore redisTokenStore) {
        this.secret = secret;
        this.mongoTokenStore = mongoTokenStore;
        this.redisTokenStore = redisTokenStore;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        signer = new MACSigner(secret);
        signatureVerifier = new MACVerifier(secret.getBytes());
    }

    public void setAccessTokenExpireTime(int accessTokenValidityMilliSeconds) {
        this.accessTokenValidityMilliSeconds = accessTokenValidityMilliSeconds;
    }

    public void setRefreshTokenExpireTime(int refreshTokenValidityMilliSeconds) {
        this.refreshTokenValidityMilliSeconds = refreshTokenValidityMilliSeconds;
    }

    /**
    * Access token is stored in mongo only for logging purposes
    * */
    public Mono<String> createAccessToken(String principal) {
        Date issueTime = new Date();
        Date expirationTime = new Date(issueTime.getTime() + accessTokenValidityMilliSeconds);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject(principal).issuer("elyor.me")
                .issueTime(issueTime).expirationTime(expirationTime).build();

        JWSHeader header = new JWSHeader.Builder(jwsAlgorithm)
                .type(type).build();
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            log.error("Error while signing accessToken: {}", e.getMessage());
            return Mono.error(new GlobalException(ErrorCode.INTERNAL_SERVER_ERROR));
        }
        String tokenValue = signedJWT.serialize();
        return this.storeAccessToken(tokenValue, principal, issueTime, expirationTime)
                .then(Mono.just(tokenValue));
    }

    /**
     * Checks the redis first.
     *    If found, store it Mongo(for the sake of logging) and return without updating Redis.
     *    If not found, create a new refresh token save it in both Redis and Mongo
     * */
    public Mono<String> createRefreshToken(String principal) {
        return redisTokenStore.findRefreshToken(principal)
                .flatMap(refreshToken -> mongoTokenStore
                        .storeRefreshToken(refreshToken)
                        .then(Mono.just(refreshToken.getValue())))
                .switchIfEmpty(createNewRefreshToken(principal));

    }

    private Mono<String> createNewRefreshToken(String principal) {
        String tokenValue = UUID.randomUUID().toString();
        Date issuedAt = new Date();
        Date expiresAt = new Date(issuedAt.getTime() + refreshTokenValidityMilliSeconds);
        RefreshToken refreshToken = new RefreshToken(tokenValue, principal, issuedAt, expiresAt);
        return mongoTokenStore.storeRefreshToken(refreshToken)
                .then(redisTokenStore.storeRefreshToken(refreshToken))
                .then(Mono.just(tokenValue));
    }

    /**
     * Read refresh token from redis not mongo.
     * Why? Performance, maybe. Need to check if it's a correct way
     *
     * */
    public Mono<String> refreshAccessToken(String email, String refreshTokenValue){
        return redisTokenStore.findRefreshToken(email)
                .filter(refreshToken -> refreshToken.getValue().equals(refreshTokenValue))
                .flatMap(refreshToken -> createAccessToken(refreshToken.getPrincipal()))
                .switchIfEmpty(Mono.error(new GlobalException(ErrorCode.INVALID_REFRESH_TOKEN)));
    }

    public Mono<JWTClaimsSet> validateAccessToken(String accessToken) {
        SignedJWT signedJWT;
        List<ErrorResponse.FieldError> errors =
                ErrorResponse.FieldError.of("accessToken", accessToken, "Verification failed");
        try {
            signedJWT = SignedJWT.parse(accessToken);
            typeVerifier.verify(signedJWT.getHeader().getType(), null);
            verifyAlgorithm(signedJWT.getHeader());
            verifyClaims(signedJWT.getJWTClaimsSet());

            if(signedJWT.verify(signatureVerifier)) {
                log.info("Access token validation successful");
                return Mono.just(signedJWT.getJWTClaimsSet());
            }
        } catch (ParseException e ) {
            log.error("JWT can't be parsed: {}",e.getMessage());
            errors = ErrorResponse.FieldError.of("Header", accessToken, "Can't be parsed");
        } catch (BadJOSEException e) {
            log.error("BadJOSEException: {} ",e.getMessage());
            errors = ErrorResponse.FieldError.of("accessToken", accessToken, e.getMessage());
        } catch (JOSEException e) {
            log.error("JOSEException: {}: ",e.getMessage());
            errors = ErrorResponse.FieldError.of("accessToken", accessToken, e.getMessage());
        }

        log.error("Access token validation failed");
        return Mono.error(new GlobalException(ErrorCode.INVALID_JWT, errors));
    }

    private void verifyAlgorithm(JWSHeader jwsHeader) throws BadJWSException {
        if(!jwsAlgorithm.equals(jwsHeader.getAlgorithm())) {
            String message = "JOSE header alg (algorithm) doesn't match expected algorithm";
            throw new BadJWSException(message);
        }
    }

    private void verifyClaims(JWTClaimsSet claimsSet) throws BadJWTException {
        if(claimsSet.getExpirationTime().before(new Date())) {
            throw BadJWTExceptions.EXPIRED_EXCEPTION;
        }
    }

    private Mono<Void> storeAccessToken(String value, String principal, Date issueTime,
                                  Date expirationTime) {
        AccessToken tokenToStore = AccessToken.builder().value(value).type(type.toString())
                .principal(principal).issuedAt(issueTime).expiresAt(expirationTime).build();
        return mongoTokenStore.storeAccessToken(tokenToStore);
    }

}
