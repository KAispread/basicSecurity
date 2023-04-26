package com.security.basicSecurity.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;

@NoArgsConstructor
@Getter
public class AccountDto {
    private String username;
    private String password;
    private String email;
    private Integer age;
    private String role;

    @Builder
    public AccountDto(String username, String password, String email, Integer age, String role) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.age = age;
        this.role = role;
    }

    public Account toEntity(PasswordEncoder passwordEncoder) {
        String encodePassword = passwordEncoder.encode(this.password);

        return Account.builder()
                .username(this.username)
                .password(encodePassword)
                .email(this.email)
                .age(this.age)
                .role(this.role)
                .build();
    }
}
