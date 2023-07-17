package com.uptalent.auth.controller;

import com.uptalent.auth.jwt.JwtService;
import com.uptalent.auth.model.request.AuthLogin;
import com.uptalent.auth.model.request.AuthRegister;
import com.uptalent.auth.model.response.JwtResponse;
import com.uptalent.auth.model.PublicKeyDTO;
import com.uptalent.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final JwtService jwtService;
    private final AuthService authService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public JwtResponse register(@Valid @RequestBody AuthRegister authRegister) {
        return authService.registerUser(authRegister);
    }

    @PostMapping("/login")
    @ResponseStatus(HttpStatus.CREATED)
    public JwtResponse login(@Valid @RequestBody AuthLogin authLogin) {
        return authService.loginUser(authLogin);
    }

    @GetMapping("/public-key")
    public PublicKeyDTO getPublicKey() {
        return jwtService.getPublicKey();
    }
}
