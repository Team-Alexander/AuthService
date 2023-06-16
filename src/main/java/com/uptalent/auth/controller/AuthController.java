package com.uptalent.auth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    @GetMapping
    public String hello() {
        return "Hello World";
    }

    @GetMapping("/test")
    public String test() {
        return "test";
    }
}
