package com.security.basicSecurity.security.manager;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.method.MethodInvocationResult;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.function.Supplier;

@Slf4j
@Component
public class AfterAuthorizationManager implements AuthorizationManager<MethodInvocationResult> {
    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocationResult object) {
        // return 값 가져오기
        Object result = object.getResult();
        log.info("AFTER AUTHORIZATION MANAGER : invoked");

        return new AuthorizationDecision(true);
    }
}
