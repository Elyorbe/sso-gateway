package me.elyor.ssogateway.authn;

import jakarta.validation.Valid;
import me.elyor.ssogateway.authn.token.TokenService;
import me.elyor.ssogateway.authn.token.common.TokenDto;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/v1/authn")
public class AuthenticationController {

    private TokenService tokenService;

    public AuthenticationController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/token/refresh")
    public Mono<ResponseEntity<TokenDto.RefreshResponse>> refreshAccessToken(
            @Valid @RequestBody TokenDto.RefreshRequest request) {
        return tokenService.refreshAccessToken(request.email, request.refreshToken)
                .map(TokenDto.RefreshResponse::new)
                .map(ResponseEntity::ok);
    }

}
