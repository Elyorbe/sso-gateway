package me.elyor.ssogateway.global.error.exception;

import me.elyor.ssogateway.global.error.ErrorResponse;
import lombok.Getter;

import java.util.List;

@Getter
public class GlobalException extends RuntimeException {

    private ErrorResponse errorResponse;

    public GlobalException(ErrorCode errorCode) {
        this.errorResponse = ErrorResponse.of(errorCode);
    }

    public GlobalException(ErrorCode errorCode, List<ErrorResponse.FieldError> errors) {
        this.errorResponse = ErrorResponse.of(errorCode, errors);
    }

}
