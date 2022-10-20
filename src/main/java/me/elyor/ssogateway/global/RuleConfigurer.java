package me.elyor.ssogateway.global;

import org.springframework.http.server.PathContainer;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class RuleConfigurer {

    private List<String> antPatterns = new ArrayList<>();
    private Access access = new Access();

    public Access pathMatchers(String... antPatterns) {
        this.antPatterns.addAll(Arrays.asList(antPatterns));
        return access;
    }

    public List<PathPattern> allowedPaths() {
        return this.access.allowedPaths;
    }

    public Mono<Boolean> isAllowed(PathContainer pathContainer) {
        return Mono.just(this.allowedPaths().stream()
                .anyMatch(pathPattern -> pathPattern.matches(pathContainer)));
    }

    public final class Access {
        private List<PathPattern> allowedPaths = new ArrayList<>();
        private PathPatternParser pathPatternParser = new PathPatternParser();

        public void permitAll() {
            for(String antPattern :  antPatterns) {
                PathPattern pathPattern = pathPatternParser.parse(antPattern);
                allowedPaths.add(pathPattern);
            }
        }
    }

}
