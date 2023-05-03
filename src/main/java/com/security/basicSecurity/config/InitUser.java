package com.security.basicSecurity.config;

import com.security.basicSecurity.domain.dto.AccountDto;
import com.security.basicSecurity.domain.entity.Account;
import com.security.basicSecurity.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

import static com.security.basicSecurity.domain.entity.Role.MANAGER;
import static com.security.basicSecurity.domain.entity.Role.USER;

@Component
public class InitUser {
    @Autowired
    private Initialize initialize;

    @PostConstruct
    public void onInit() {
        initialize.init();
    }

    @RequiredArgsConstructor
    @Component
    @Transactional
    static class Initialize {
        private final UserRepository userRepository;
        private final PasswordEncoder passwordEncoder;

        public void init() {
            List<Account> accountList = new ArrayList<>();

            AccountDto kai = AccountDto.builder()
                    .username("kai")
                    .password("1234")
                    .age(26)
                    .email("email1@email.com")
                    .role(USER.name())
                    .build();

            AccountDto ija = AccountDto.builder()
                    .username("ija")
                    .password("1234")
                    .age(26)
                    .email("email1@email.com")
                    .role(MANAGER.name())
                    .build();


            accountList.add(kai.toEntity(passwordEncoder));
            accountList.add(ija.toEntity(passwordEncoder));
            userRepository.saveAll(accountList);
        }
    }
}
