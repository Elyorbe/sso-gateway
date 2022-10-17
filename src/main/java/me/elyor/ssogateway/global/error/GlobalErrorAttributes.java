package me.elyor.ssogateway.global.error;

import me.elyor.ssogateway.global.error.exception.GlobalException;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.reactive.error.DefaultErrorAttributes;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;

import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class GlobalErrorAttributes extends DefaultErrorAttributes {

    @Override
    public Map<String, Object> getErrorAttributes(ServerRequest request, ErrorAttributeOptions options) {
        Throwable error = getError(request);
        if(error instanceof GlobalException exception) {
            Map<String, Object> errorAttributes = new LinkedHashMap<>();
            ErrorResponse response =  exception.getErrorResponse();
            errorAttributes.put("status", response.getStatus());
            errorAttributes.put("message", response.getMessage());
            errorAttributes.put("errors", response.getErrors());
            return errorAttributes;
        }

        return super.getErrorAttributes(request, options);
    }
}
