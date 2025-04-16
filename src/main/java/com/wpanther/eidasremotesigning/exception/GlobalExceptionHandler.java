package com.wpanther.eidasremotesigning.exception;

import com.wpanther.eidasremotesigning.controller.CSCOAuth2Controller.CSCOAuth2Exception;
import com.wpanther.eidasremotesigning.dto.csc.CSCErrorResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;

import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
@Slf4j
@Order(Ordered.HIGHEST_PRECEDENCE)
public class GlobalExceptionHandler {

    @ExceptionHandler(CertificateException.class)
    public ResponseEntity<ErrorResponse> handleCertificateException(CertificateException ex) {
        log.error("Certificate error", ex);
        return createErrorResponse(ex.getMessage(), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(SigningException.class)
    public ResponseEntity<ErrorResponse> handleSigningException(SigningException ex) {
        log.error("Signing error", ex);
        return createErrorResponse(ex.getMessage(), HttpStatus.BAD_REQUEST);
    }
    
    @ExceptionHandler(ClientRegistrationException.class)
    public ResponseEntity<ErrorResponse> handleClientRegistrationException(ClientRegistrationException ex) {
        log.error("Client registration error", ex);
        return createErrorResponse(ex.getMessage(), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ValidationErrorResponse> handleValidationExceptions(MethodArgumentNotValidException ex) {
        log.error("Validation error", ex);
        
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        
        ValidationErrorResponse errorResponse = new ValidationErrorResponse(
            "Validation failed",
            HttpStatus.BAD_REQUEST.value(),
            Instant.now(),
            errors
        );
        
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }
    
    /**
     * Handle OAuth2 exceptions for CSC API
     */
    @ExceptionHandler(CSCOAuth2Exception.class)
    public ResponseEntity<Map<String, Object>> handleOAuth2Exception(CSCOAuth2Exception ex) {
        log.error("OAuth2 error: {}", ex.getMessage());
        
        Map<String, Object> error = new HashMap<>();
        error.put("error", ex.getError());
        error.put("error_description", ex.getMessage());
        
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }
    
    /**
     * Handle CSC API exceptions using the CSC error format
     */
    @ExceptionHandler({Exception.class})
    public ResponseEntity<Object> handleException(Exception ex, WebRequest request) {
        log.error("Unexpected error", ex);
        
        String path = ((ServletWebRequest)request).getRequest().getRequestURI();
        
        // Check if it's a CSC API request
        if (path.startsWith("/csc/v2/")) {
            CSCErrorResponse errorResponse = CSCErrorResponse.builder()
                    .error("server.error")
                    .message("An unexpected error occurred: " + ex.getMessage())
                    .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .path(path)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            
            return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        
        // Default error format
        ErrorResponse errorResponse = new ErrorResponse(
            "An unexpected error occurred: " + ex.getMessage(),
            HttpStatus.INTERNAL_SERVER_ERROR.value(),
            Instant.now()
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private ResponseEntity<ErrorResponse> createErrorResponse(String message, HttpStatus status) {
        ErrorResponse errorResponse = new ErrorResponse(
            message,
            status.value(),
            Instant.now()
        );
        return new ResponseEntity<>(errorResponse, status);
    }

    // Error response classes
    public static class ErrorResponse {
        private final String message;
        private final int status;
        private final Instant timestamp;

        public ErrorResponse(String message, int status, Instant timestamp) {
            this.message = message;
            this.status = status;
            this.timestamp = timestamp;
        }

        public String getMessage() {
            return message;
        }

        public int getStatus() {
            return status;
        }

        public Instant getTimestamp() {
            return timestamp;
        }
    }
    
    public static class ValidationErrorResponse extends ErrorResponse {
        private final Map<String, String> errors;

        public ValidationErrorResponse(String message, int status, Instant timestamp, Map<String, String> errors) {
            super(message, status, timestamp);
            this.errors = errors;
        }

        public Map<String, String> getErrors() {
            return errors;
        }
    }
}