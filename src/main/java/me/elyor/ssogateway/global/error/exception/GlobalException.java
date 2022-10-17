package me.elyor.ssogateway.global.error.exception;

import me.elyor.ssogateway.global.error.ErrorResponse;
import lombok.Getter;

@Getter
public class GlobalException extends RuntimeException {
    private ErrorResponse errorResponse;

    public GlobalException(ErrorCode errorCode) {
        this.errorResponse = ErrorResponse.of(errorCode);
    }
}
