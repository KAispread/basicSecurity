package com.security.basicSecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.basicSecurity.security.token.AjaxAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.thymeleaf.util.StringUtils;

import java.io.IOException;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {
    private final ObjectMapper objectMapper;
    private final AuthenticationManager authenticationManager;
    private static final String LOGIN_URL = "/api/login";

    public AjaxLoginProcessingFilter(ObjectMapper objectMapper, AuthenticationManager authenticationManager) {
        super(new AntPathRequestMatcher(LOGIN_URL), authenticationManager);
        this.authenticationManager = authenticationManager;
        this.objectMapper = objectMapper;
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        if (!isAjax(request)) {
            throw new IllegalStateException("Authentication is not supported");
        }
        
        LoginDto accountDto = objectMapper.readValue(request.getInputStream(), LoginDto.class);
        validUsernamePasswordInput(accountDto);
        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountDto.username(), accountDto.password());

        return authenticationManager.authenticate(ajaxAuthenticationToken);
    }

    private static void validUsernamePasswordInput(LoginDto accountDto) {
        if (StringUtils.isEmpty(accountDto.username()) || StringUtils.isEmpty(accountDto.password())) {
            throw new IllegalArgumentException("Username or Password is empty");
        }
    }

    private static boolean isAjax(HttpServletRequest request) {
        return "XMLHttpRequest".equals(request.getHeader("X-Requested-With"));
    }

    record LoginDto(String username, String password) {}
}
