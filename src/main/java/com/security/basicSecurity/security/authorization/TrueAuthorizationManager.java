package com.security.basicSecurity.security.authorization;

import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;

import java.util.function.Supplier;

// Manager
@Slf4j
public class TrueAuthorizationManager implements AuthorizationManager<MethodInvocation> {
    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocation object) {
        log.info("TRUE AUTHORIZATION MANAGER : invoked");

        return new AuthorizationDecision(authentication.get().isAuthenticated());
    }
}
