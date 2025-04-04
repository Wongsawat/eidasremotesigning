package com.wpanther.eidasremotesigning.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class SigningException extends RuntimeException {
    
    public SigningException(String message) {
        super(message);
    }
    
    public SigningException(String message, Throwable cause) {
        super(message, cause);
    }
}