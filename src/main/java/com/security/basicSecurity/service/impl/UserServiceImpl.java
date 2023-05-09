package com.security.basicSecurity.service.impl;

import com.security.basicSecurity.domain.Account;
import com.security.basicSecurity.repository.UserRepository;
import com.security.basicSecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@RequiredArgsConstructor
@Transactional
@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }

    @Override
    @PreAuthorize("hasRole('ROLE_MANAGER') and @userRepository.findByUsername(#username).get().age >= 30")
    public void order(String username) {
        log.info("ROLE_USER & AGE >= 30 : order has been occur");
    }

    @Override
    @PostAuthorize("returnObject.age() >= 30")
    public Elder eventForElder(String username) {
        Account account = userRepository.findByUsername(username).get();
        return new Elder(account.getUsername(), account.getAge());
    }

    public record Elder(String username, int age) {}
}
