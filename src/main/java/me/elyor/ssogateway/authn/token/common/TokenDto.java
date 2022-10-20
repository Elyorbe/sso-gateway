package me.elyor.ssogateway.authn.token.common;

public class TokenDto {

    public static class RefreshRequest {
        public String refreshToken;
        public String email;
    }

    public static class RefreshResponse {
        public String accessToken;
        public RefreshResponse(String accessToken) {
            this.accessToken = accessToken;
        }
    }

}
