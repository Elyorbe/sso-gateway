package me.elyor.ssogateway.global.error.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorCode {
    ACCESS_DENIED("Access Denied", HttpStatus.FORBIDDEN.value()),
    UNAUTHORIZED("Unauthorized", HttpStatus.UNAUTHORIZED.value());

    private final String message;
    private final int status;

    ErrorCode(String message, int status) {
        this.status = status;
        this.message = message;
    }
}
