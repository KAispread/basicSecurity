package com.security.basicSecurity.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.basicSecurity.security.filter.AjaxLoginProcessingFilter;
import com.security.basicSecurity.security.handler.AjaxAuthenticationFailureHandler;
import com.security.basicSecurity.security.handler.AjaxAuthenticationSuccessHandler;
import com.security.basicSecurity.security.handler.CustomAccessDeniedHandler;
import com.security.basicSecurity.security.provider.AjaxAuthenticationProvider;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;

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
}
