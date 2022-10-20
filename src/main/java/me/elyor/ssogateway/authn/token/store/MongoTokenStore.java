package me.elyor.ssogateway.authn.token.store;

import me.elyor.ssogateway.authn.token.common.AccessToken;
import me.elyor.ssogateway.authn.token.common.RefreshToken;
import org.springframework.data.mongodb.core.ReactiveMongoOperations;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class MongoTokenStore {

    private static final String ACCESS_TOKEN_COLLECTION = "accessTokens";
    private static final String REFRESH_TOKEN_COLLECTION = "refreshTokens";

    private ReactiveMongoOperations mongoOps;

    public MongoTokenStore(ReactiveMongoOperations mongoOps) {
        this.mongoOps = mongoOps;
    }

    public Mono<Void> storeAccessToken(AccessToken accessToken) {
        return mongoOps.insert(accessToken, ACCESS_TOKEN_COLLECTION).then();
    }

    public Mono<Void> storeRefreshToken(RefreshToken refreshToken) {
        return mongoOps.insert(refreshToken, REFRESH_TOKEN_COLLECTION).then();
    }

}
