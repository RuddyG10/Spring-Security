package com.example.springsecurity.Controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Controller
public class UserController {
    @GetMapping("/welcome")
    public String welcome(){
        return "Welcome";
    }

    @GetMapping("/")
    public String homePage(){
        return "home";
    }
    @GetMapping("/logout")
    public String logout(){
        return "redirect:/home";
    }
}
