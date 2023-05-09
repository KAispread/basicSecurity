package com.security.basicSecurity.controller.user;

import com.security.basicSecurity.domain.Account;
import com.security.basicSecurity.domain.AccountDto;
import com.security.basicSecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@RequiredArgsConstructor
@Controller
public class UserController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @GetMapping("/mypage")
    public String myPage() throws Exception {
        return "user/mypage";
    }

    @GetMapping("/users")
    public String createUser() {
        return "user/login/register";
    }

    @PostMapping("/users")
    public String createUser(AccountDto accountDto) {
        Account account = accountDto.toEntity(passwordEncoder);

        userService.createUser(account);
        return "redirect:/";
    }
}
