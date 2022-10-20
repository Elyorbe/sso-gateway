package me.elyor.ssogateway.global.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "app")
public record AppProperties(
        Cors cors
) {}

record Cors(
        List<String> allowedOrigins,
        List<String> allowedMethods
) {}
