package com.uptalent.auth.controller;

import com.uptalent.auth.jwt.JwtService;
import com.uptalent.auth.model.AuthRegister;
import com.uptalent.auth.model.AuthResponse;
import com.uptalent.auth.model.PublicKeyDTO;
import com.uptalent.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final JwtService jwtService;
    private final AuthService authService;

    @PostMapping("/register")
    @PreAuthorize("permitAll()")
    public AuthResponse register(@Valid @RequestBody AuthRegister authRegister) {
        return authService.registerUser(authRegister);
    }

    @GetMapping("/test")
    @PreAuthorize("permitAll()")
    public String readJwt() {
        return "test";
    }


    @GetMapping("/secret")
    @PreAuthorize("isAuthenticated()")
    public String secret() {
        return "secret";
    }

    @GetMapping("/public-key")
    public PublicKeyDTO getPublicKey() {
        return jwtService.getPublicKey();
    }
}
