package com.security.basicSecurity.security.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final RequestCache requestCache = new HttpSessionRequestCache();
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 사용자의 이전 요청 정보를 담고있는 객체
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        // 인증 성공시 Default 로 보낼 URL 설정
        setDefaultTargetUrl("/");

        // 인증 예외로 인해 로그인 페이지로 redirect 된 경우
        if (savedRequest != null) {
            String targetUrl = savedRequest.getRedirectUrl();

            if (!targetUrl.contains("login?")) redirectStrategy.sendRedirect(request, response, targetUrl);
            return;
        }

        // 기본 값으로 설정해놓은 페이지로 이동
        redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl());
    }
}
