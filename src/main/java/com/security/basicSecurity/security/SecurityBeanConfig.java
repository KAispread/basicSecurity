package com.security.basicSecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityBeanConfig {
    @Bean
    public UserDetailsManager userDetailsManager() {
        UserDetails kai = User.builder()
                .username("kai")
                .password("{noop}1111")
                .roles("USER")
                .build();

        UserDetails kang = User.builder()
                .username("kang")
                .password("{noop}1111")
                .roles("SYS")
                .build();

        UserDetails admin = User.builder()
                .username("basco")
                .password("{noop}1111")
                .roles("ADMIN", "SYS", "USER")
                .build();

        return new InMemoryUserDetailsManager(kai, kang, admin);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .headers().frameOptions().sameOrigin()
                .and()
                .securityMatcher("/user/**")
                .authorizeHttpRequests(authorize ->
                        authorize
                                .requestMatchers("/user").hasRole("USER")
                                .requestMatchers("/h2-console/**").permitAll()
                                .anyRequest().permitAll()
                );


        return http.build();
    }
}
