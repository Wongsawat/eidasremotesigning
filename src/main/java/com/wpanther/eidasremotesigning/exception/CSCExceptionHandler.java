package com.wpanther.eidasremotesigning.exception;

import java.time.Instant;

import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;

import com.wpanther.eidasremotesigning.dto.csc.CSCErrorResponse;

import lombok.extern.slf4j.Slf4j;

/**
 * Exception handler for CSC API endpoints
 * Formats error responses according to the CSC API specification
 */
@ControllerAdvice(basePackages = "com.wpanther.eidasremotesigning.controller")
@Order(1) // Higher priority than the global exception handler
@Slf4j
public class CSCExceptionHandler {

    /**
     * Handle CSC API exceptions for certificate operations
     */
    @ExceptionHandler(CertificateException.class)
    public ResponseEntity<CSCErrorResponse> handleCertificateException(CertificateException ex, WebRequest request) {
        log.error("Certificate error in CSC API", ex);
        return createCSCErrorResponse("certificate.error", ex.getMessage(), HttpStatus.BAD_REQUEST, request);
    }

    /**
     * Handle CSC API exceptions for signing operations
     */
    @ExceptionHandler(SigningException.class)
    public ResponseEntity<CSCErrorResponse> handleSigningException(SigningException ex, WebRequest request) {
        log.error("Signing error in CSC API", ex);
        return createCSCErrorResponse("signing.error", ex.getMessage(), HttpStatus.BAD_REQUEST, request);
    }

    /**
     * Handle CSC API exceptions for client registration
     */
    @ExceptionHandler(ClientRegistrationException.class)
    public ResponseEntity<CSCErrorResponse> handleClientRegistrationException(
            ClientRegistrationException ex, WebRequest request) {
        log.error("Client registration error in CSC API", ex);
        return createCSCErrorResponse("registration.error", ex.getMessage(), HttpStatus.BAD_REQUEST, request);
    }

    /**
     * Handle unexpected errors in CSC API
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<CSCErrorResponse> handleGenericException(Exception ex, WebRequest request) {
        log.error("Unexpected error in CSC API", ex);
        return createCSCErrorResponse(
                "unexpected.error", 
                "An unexpected error occurred: " + ex.getMessage(),
                HttpStatus.INTERNAL_SERVER_ERROR, 
                request);
    }

    /**
     * Creates a CSC API error response
     */
    private ResponseEntity<CSCErrorResponse> createCSCErrorResponse(
            String error, String message, HttpStatus status, WebRequest request) {
        
        String path = ((ServletWebRequest)request).getRequest().getRequestURI();
        
        CSCErrorResponse errorResponse = CSCErrorResponse.builder()
                .error(error)
                .message(message)
                .status(status.value())
                .path(path)
                .timestamp(Instant.now().toEpochMilli())
                .build();
        
        return new ResponseEntity<>(errorResponse, status);
    }
}