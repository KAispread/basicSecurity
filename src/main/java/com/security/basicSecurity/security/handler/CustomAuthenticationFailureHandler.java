package com.security.basicSecurity.security.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    private static final String USERNAME_PASSWORD_ERROR_MESSAGE = "INVALID USERNAME OR PASSWORD";
    private static final String SECRET_KEY_ERROR_MESSAGE = "INVALID SECRET KEY";

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String errorMessage = USERNAME_PASSWORD_ERROR_MESSAGE;

        if (exception instanceof InsufficientAuthenticationException) {
            errorMessage = SECRET_KEY_ERROR_MESSAGE;
        }

        setDefaultFailureUrl("/login?error=true&exception=" + errorMessage);

        super.onAuthenticationFailure(request, response, exception);
    }
}
