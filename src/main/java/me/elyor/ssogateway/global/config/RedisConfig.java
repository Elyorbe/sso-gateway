package me.elyor.ssogateway.global.config;

import me.elyor.ssogateway.authn.token.common.RefreshToken;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {

    private ReactiveRedisConnectionFactory connectionFactory;

    public RedisConfig(ReactiveRedisConnectionFactory connectionFactory) {
        this.connectionFactory = connectionFactory;
    }

    @Bean
    public ReactiveRedisTemplate<String, RefreshToken> reactiveRedisTemplateRefreshToken() {
        var keySerializer = new StringRedisSerializer();
        var valueSerializer = new Jackson2JsonRedisSerializer<>(RefreshToken.class);
        RedisSerializationContext.RedisSerializationContextBuilder<String, RefreshToken>
                builder = RedisSerializationContext.newSerializationContext(keySerializer);
        RedisSerializationContext<String, RefreshToken> context = builder
                .value(valueSerializer).build();
        return new ReactiveRedisTemplate<>(this.connectionFactory, context);
    }

}
