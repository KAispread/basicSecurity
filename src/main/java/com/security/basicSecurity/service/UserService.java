package com.security.basicSecurity.service;

import com.security.basicSecurity.domain.Account;
import com.security.basicSecurity.service.impl.UserServiceImpl;

public interface UserService {
    void createUser(Account account);
    void order(String username);
    UserServiceImpl.Elder eventForElder(String username);
}
