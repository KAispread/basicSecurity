package com.security.basicSecurity.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.basicSecurity.domain.entity.Role;
import com.security.basicSecurity.security.authorization.TrueAuthorizationManager;
import com.security.basicSecurity.security.filter.AjaxLoginProcessingFilter;
import com.security.basicSecurity.security.filter.CustomAuthorizationFilter;
import com.security.basicSecurity.security.handler.AjaxAuthenticationFailureHandler;
import com.security.basicSecurity.security.handler.AjaxAuthenticationSuccessHandler;
import com.security.basicSecurity.security.handler.CustomAccessDeniedHandler;
import com.security.basicSecurity.security.provider.AjaxAuthenticationProvider;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Advisor;
import org.springframework.aop.support.JdkRegexpMethodPointcut;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.method.*;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import static org.springframework.http.HttpMethod.GET;

@Configuration
public class SecurityBeanConfig {
    // PasswordEncoder
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // WebIgnore
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web -> {
            web.ignoring().requestMatchers(PathRequest.toH2Console());
            web.ignoring().requestMatchers("/css/**", "/js/**","/images/**", "/error", "/favicon.ico");
        });
    }

    // 인가 예외 핸들러
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration, AjaxAuthenticationProvider ajaxAuthenticationProvider) throws Exception {
        ProviderManager providerManager = (ProviderManager) authenticationConfiguration.getAuthenticationManager();
        providerManager.getProviders().add(ajaxAuthenticationProvider);
        return providerManager;
    }

    // Ajax 로그인 처리 필터
    @Bean
    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter(ObjectMapper objectMapper, AuthenticationManager authenticationManager) {
        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter(objectMapper, authenticationManager);

        ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());
        ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler());

        return ajaxLoginProcessingFilter;
    }

    @Bean
    public AjaxAuthenticationSuccessHandler ajaxAuthenticationSuccessHandler() {
        return new AjaxAuthenticationSuccessHandler();
    }

    @Bean
    public AjaxAuthenticationFailureHandler ajaxAuthenticationFailureHandler() {
        return new AjaxAuthenticationFailureHandler();
    }

    // 인가 필터 커스터마이징
    @Bean
    public CustomAuthorizationFilter customAuthorizationFilter(HandlerMappingIntrospector introspector) {
        MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);
        RequestMatcher customPath = new AndRequestMatcher(
                mvcMatcherBuilder.pattern(GET, "/custom")
        );
        RequestMatcher any = AnyRequestMatcher.INSTANCE;

        RequestMatcherDelegatingAuthorizationManager authorizationManager = RequestMatcherDelegatingAuthorizationManager.builder()
                .add(customPath, authorityAuthorizationManager(Role.USER.name()))
                .add(any, new AuthenticatedAuthorizationManager<>())
                .build();

        return new CustomAuthorizationFilter(authorizationManager);
    }

    public AuthorityAuthorizationManager<RequestAuthorizationContext> authorityAuthorizationManager(String roleName) {
        AuthorityAuthorizationManager<RequestAuthorizationContext> authorityAuthorizationManager = AuthorityAuthorizationManager.hasAnyAuthority(roleName);
        authorityAuthorizationManager.setRoleHierarchy(roleHierarchy());
        return authorityAuthorizationManager;
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy(
                """
                        ADMIN > MANAGER
                        MANAGER > USER
                        USER > GUEST
                """
        );
        return roleHierarchy;
    }


    // PreAuthorize 어노테이션에 권한 계층을 설정
    @Bean
    public DefaultMethodSecurityExpressionHandler methodSecurityExpressionHandler() {
        DefaultMethodSecurityExpressionHandler defaultMethodSecurityExpressionHandler = new DefaultMethodSecurityExpressionHandler();
        defaultMethodSecurityExpressionHandler.setRoleHierarchy(roleHierarchy());
        return defaultMethodSecurityExpressionHandler;
    }

    // Method 인가 처리 순서 지정
    @Bean
    public Advisor postFilterAuthorizationMethodInterceptor() {
        PostFilterAuthorizationMethodInterceptor interceptor = new PostFilterAuthorizationMethodInterceptor();
        interceptor.setOrder(AuthorizationInterceptorsOrder.POST_AUTHORIZE.getOrder() - 1);
        return interceptor;
    }

    // custom before-method AuthorizationManager
    @Bean
    public Advisor customAuthorize() {
        JdkRegexpMethodPointcut pattern = new JdkRegexpMethodPointcut();
        pattern.setPattern("com.security.basicSecurity.aopsecurity.AopSecurityController.*(..)");

        // 커스텀 Manager 지정
        AuthorizationManager<MethodInvocation> rule = trueAuthorizationManager();

        // 특정 인터셉터 이전에 수행됨
        AuthorizationManagerBeforeMethodInterceptor interceptor =
                new AuthorizationManagerBeforeMethodInterceptor(pattern, rule);
        interceptor.setOrder(AuthorizationInterceptorsOrder.PRE_AUTHORIZE.getOrder() + 1);
        return interceptor;
    }

    // custom after-method AuthorizationManager
    @Bean
    public Advisor customAuthorizeAfterMethod(AuthorizationManager<MethodInvocationResult> rule) {
        // Annotation 기반 point cut
        AnnotationMatchingPointcut pointcut = new AnnotationMatchingPointcut(PreAuthorize.class);

        AuthorizationManagerAfterMethodInterceptor interceptor = new AuthorizationManagerAfterMethodInterceptor(pointcut, rule);
        interceptor.setOrder(AuthorizationInterceptorsOrder.POST_AUTHORIZE.getOrder() + 1);
        return interceptor;
    }

    @Bean
    public AuthorizationManager<MethodInvocation> trueAuthorizationManager() {
        return new TrueAuthorizationManager();
    }
}
