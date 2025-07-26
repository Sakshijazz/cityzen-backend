package com.cityzen.auth.exception;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import jakarta.persistence.EntityNotFoundException;
@ControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(CustomException.class)
    public ResponseEntity<String> handleCustomException(CustomException ex) {
        // Handle custom exceptions
        return new ResponseEntity<>(ex.getMessage(), ex.getStatus());
    }
    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<String> handleEntityNotFoundException(EntityNotFoundException ex) {
        // Handle entity not found exceptions
        return new ResponseEntity<>("Resource not found: " + ex.getMessage(), HttpStatus.NOT_FOUND);
    }
    @ExceptionHandler(OTPMismatchException.class) // Create this custom exception class
    public ResponseEntity<String> handleOtpMismatch(OTPMismatchException ex) {
        // Handle OTP mismatch exceptions
        return new ResponseEntity<>("Invalid OTP provided.", HttpStatus.BAD_REQUEST);
    }
    @ExceptionHandler(TokenExpiredException.class) // Create this custom exception class
    public ResponseEntity<String> handleTokenExpired(TokenExpiredException ex) {
        // Handle expired token exceptions
        return new ResponseEntity<>("Token has expired. Please log in again.", HttpStatus.UNAUTHORIZED);
    }
    @ExceptionHandler(BadCredentialsException.class) // Create this custom exception class
    public ResponseEntity<String> handleBadCredentials(BadCredentialsException ex) {
        // Handle bad credentials exceptions
        return new ResponseEntity<>("Invalid credentials provided.", HttpStatus.UNAUTHORIZED);
    }
}