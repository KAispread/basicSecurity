package com.security.basicSecurity.controller.user;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@Controller
public class MessageController {

    @ResponseStatus(HttpStatus.OK)
    @GetMapping("/message")
    public String messages() {
        return "user/messages";
    }

    @ResponseBody
    @GetMapping("/api/messages")
    public String apiMessages() {
        return "messages ok";
    }
}
