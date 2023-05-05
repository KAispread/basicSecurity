package com.security.basicSecurity.security.filter;

import com.security.basicSecurity.security.provider.CustomAuthenticationProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.function.Supplier;

public class CustomAuthorizationFilter extends OncePerRequestFilter {
    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();

    private final AuthorizationManager<HttpServletRequest> authorizationManager;

    private AuthorizationEventPublisher eventPublisher = CustomAuthorizationFilter::noPublish;

    private boolean observeOncePerRequest = false;

    public CustomAuthorizationFilter(AuthorizationManager<HttpServletRequest> authorizationManager) {
        Assert.notNull(authorizationManager, "authorizationManager cannot be null");
        this.authorizationManager = authorizationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        checkAuthorization(request, response, filterChain);
    }

    public void checkAuthorization(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (this.observeOncePerRequest && isApplied(request)) {
            chain.doFilter(request, response);
            return;
        }

        String alreadyFilteredAttributeName = getAlreadyFilteredAttributeName();
        request.setAttribute(alreadyFilteredAttributeName, Boolean.TRUE);
        try {
            AuthorizationDecision decision = new AuthorizationDecision(true);
            if (getAuthentication() != null) {
                decision = this.authorizationManager.check(this::getAuthentication, request);
            }
            this.eventPublisher.publishAuthorizationEvent(this::getAuthentication, request, decision);
            if (decision != null && !decision.isGranted()) {
                throw new AccessDeniedException("Access Denied");
            }
            chain.doFilter(request, response);
        }
        finally {
            request.removeAttribute(alreadyFilteredAttributeName);
        }
    }

    private boolean isApplied(HttpServletRequest request) {
        return request.getAttribute(getAlreadyFilteredAttributeName()) != null;
    }

    public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
        Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
        this.securityContextHolderStrategy = securityContextHolderStrategy;
    }

    private Authentication getAuthentication() {
        Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
        return authentication;
    }

    public void setAuthorizationEventPublisher(AuthorizationEventPublisher eventPublisher) {
        Assert.notNull(eventPublisher, "eventPublisher cannot be null");
        this.eventPublisher = eventPublisher;
    }

    public AuthorizationManager<HttpServletRequest> getAuthorizationManager() {
        return this.authorizationManager;
    }


    private static <T> void noPublish(Supplier<Authentication> authentication, T object,
                                      AuthorizationDecision decision) {

    }

    public boolean isObserveOncePerRequest() {
        return this.observeOncePerRequest;
    }

    public void setObserveOncePerRequest(boolean observeOncePerRequest) {
        this.observeOncePerRequest = observeOncePerRequest;
    }
}
