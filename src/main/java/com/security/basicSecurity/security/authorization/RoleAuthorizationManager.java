package com.security.basicSecurity.security.authorization;

import com.security.basicSecurity.domain.entity.Role;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;

public class RoleAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {
    private final List<String> requiredRoles = new ArrayList<>();

    public RoleAuthorizationManager(Role role) {
        super();
        requiredRoles.add(role.name());
    }

    public RoleAuthorizationManager(Role... roles) {
        super();
        Arrays.stream(roles)
                .forEach(role -> requiredRoles.add(role.name()));
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        boolean decision = true;

        if (!requiredRoles.isEmpty()) {
            decision = authentication.get().getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .anyMatch(requiredRoles::contains);
        }

        System.out.println("INVOKED MANAGER - CHECK METHOD");
        return new AuthorizationDecision(decision);
    }
}
