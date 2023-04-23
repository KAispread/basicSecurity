package com.security.basicSecurity.controller.user;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class MessageController {

    @GetMapping("/message")
    public String messages() {
        return "user/messages";
    }

}
