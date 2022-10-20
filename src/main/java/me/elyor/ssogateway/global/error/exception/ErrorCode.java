package me.elyor.ssogateway.global.error.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorCode {
    ACCESS_DENIED("Access denied", HttpStatus.FORBIDDEN.value()),
    UNAUTHORIZED("Unauthorized", HttpStatus.UNAUTHORIZED.value()),
    INTERNAL_SERVER_ERROR("Internal server error", HttpStatus.INTERNAL_SERVER_ERROR.value()),
    BAD_REQUEST("Bad request", HttpStatus.BAD_REQUEST.value()),
    INVALID_REFRESH_TOKEN("Refresh token is not valid", HttpStatus.BAD_REQUEST.value()),
    INVALID_JWT("JWT is not valid", HttpStatus.BAD_REQUEST.value());

    private final String message;
    private final int status;

    ErrorCode(String message, int status) {
        this.status = status;
        this.message = message;
    }
}
