package me.elyor.ssogateway.authn.token.store;

import me.elyor.ssogateway.authn.token.common.RefreshToken;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;

@Component
public class RedisTokenStore {

    private static final String REFRESH_TOKEN_KEY_PREFIX = "token:refresh:";
    private ReactiveRedisTemplate<String, RefreshToken> redisTemplate;

    public RedisTokenStore(ReactiveRedisTemplate<String, RefreshToken> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public Mono<Void> storeRefreshToken(RefreshToken refreshToken) {
        String key = REFRESH_TOKEN_KEY_PREFIX + refreshToken.getPrincipal();
        Duration timeout = Duration.between(Instant.now(), refreshToken.getExpiresAt().toInstant());
        return redisTemplate.opsForValue()
                .set(key, refreshToken, timeout).then();
    }

    public Mono<RefreshToken> findRefreshToken(String principal) {
        return redisTemplate.opsForValue().get(REFRESH_TOKEN_KEY_PREFIX + principal);
    }

}
