package org.ak.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.text.ParseException;

@ControllerAdvice
public class RestResponseEntityExceptionHandler
        extends ResponseEntityExceptionHandler {

    @ExceptionHandler({ AccessDeniedException.class })
    public ResponseEntity<Object> handleAccessDeniedException(
            Exception ex, WebRequest request) {
        logger.error("Access denied due to insufficient privileges", ex);
        return new ResponseEntity<Object>(
                "Access denied due to insufficient privileges", new HttpHeaders(), HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler({ AuthenticationException.class, InvalidBearerTokenException.class, BadJwtException.class, ParseException.class })
    public ResponseEntity<Object> handleInvalidBearerTokenException(
            Exception ex, HttpServletRequest request) {
        logger.error("Invalid jwt Bearer token used in the request", ex);
        return new ResponseEntity<Object>(
                "Invalid jwt Bearer token used in the request", new HttpHeaders(), HttpStatus.FORBIDDEN);
    }

}