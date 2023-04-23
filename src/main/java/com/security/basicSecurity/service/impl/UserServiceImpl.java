package com.security.basicSecurity.service.impl;

import com.security.basicSecurity.domain.Account;
import com.security.basicSecurity.repository.UserRepository;
import com.security.basicSecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Transactional
@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
