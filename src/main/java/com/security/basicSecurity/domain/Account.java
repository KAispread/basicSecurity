package com.security.basicSecurity.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.*;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
public class Account {
    @Id @GeneratedValue
    private Long id;
    private String username;
    private String password;
    private String email;
    private Integer age;
    private String role;

    @Builder
    public Account(String username, String password, String email, Integer age, String role) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.age = age;
        this.role = role;
    }

    public void setPassword(final String encodePassword) {
        this.password = encodePassword;
    }
}
