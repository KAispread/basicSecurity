package com.security.basicSecurity.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import static com.security.basicSecurity.domain.Role.*;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig {
    private final UserDetailsService userDetailsService;
    private final AuthenticationProvider authenticationProvider;
    private final AuthenticationDetailsSource detailsSource;
    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;
    private final AccessDeniedHandler accessDeniedHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .headers().frameOptions().sameOrigin();

        // userDetailsService & authenticationProvider 지정
        http
                .userDetailsService(userDetailsService)
                .authenticationProvider(authenticationProvider);

        http
                .authorizeHttpRequests(
                        authorize -> authorize
                                .requestMatchers("/", "/h2-console", "/login?*", "/login?**", "/users", "/login?error*").permitAll()
                                .requestMatchers("/mypage").hasRole(USER.name())
                                .requestMatchers("/message").hasRole(MANAGER.name())
                                .requestMatchers("/config").hasRole(ADMIN.name())
                                .anyRequest().permitAll()
                );

        // 로그인
        http
                .formLogin()
                .loginPage("/login")
                .defaultSuccessUrl("/")
                // 로그인 form 의 action url 과 동일해야함
                .loginProcessingUrl("/login_proc")
                // 추가 정보 저장
                .authenticationDetailsSource(detailsSource)

                // 성공, 실패 핸들러
                .successHandler(successHandler)
                .failureHandler(failureHandler)
                .permitAll();

        http
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler);

        return http.build();
    }
}
