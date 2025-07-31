package com.study.spring.domain.security.exception;

public class CustomJWTException extends RuntimeException {

    public CustomJWTException(String message) {
        super(message);
    }
}
