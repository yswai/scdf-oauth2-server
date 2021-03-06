package co.springcoders.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class UserController {

    @GetMapping("/user/status/check")
    public String getStatus() {
        return "Server is up";
    }

    @RequestMapping({"/user", "/me"})
    public Principal user(Principal principal) {
        return principal;
    }
}