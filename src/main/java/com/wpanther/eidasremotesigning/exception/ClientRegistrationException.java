package com.wpanther.eidasremotesigning.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class ClientRegistrationException extends RuntimeException {
    public ClientRegistrationException(String message) {
        super(message);
    }
}
