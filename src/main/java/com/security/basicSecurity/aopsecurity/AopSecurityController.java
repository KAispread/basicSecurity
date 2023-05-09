package com.security.basicSecurity.aopsecurity;

import com.security.basicSecurity.domain.AccountDto;
import com.security.basicSecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;

@Slf4j
@RequiredArgsConstructor
@Controller
public class AopSecurityController {
    private final UserService userService;

    @GetMapping("/preAuthorize")
    @PreAuthorize("hasRole('MANAGER')")
    public String preAuthorize(AccountDto accountDto, Model model, Principal principal) {
        model.addAttribute("method", "Success PreAuthorize");
        return "aop/method";
    }

    @GetMapping("/order")
    public String order(@RequestParam String username) {
        userService.order(username);
        return "redirect:/";
    }

    @GetMapping("/elder")
    public String elder(@RequestParam String username) {
        userService.eventForElder(username);
        log.info("ROLE_USER & AGE >= 30 : elder event has been occur");
        return "redirect:/";
    }
}
