package io.github.uptalent.auth.controller;

import io.github.uptalent.auth.jwt.JwtService;
import io.github.uptalent.auth.model.request.AuthLogin;
import io.github.uptalent.auth.model.request.AuthRegister;
import io.github.uptalent.auth.model.response.JwtResponse;
import io.github.uptalent.auth.model.common.PublicKeyDTO;
import io.github.uptalent.auth.service.AuthService;
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
        return authService.loginAccount(authLogin);
    }

    @GetMapping("/public-key")
    public PublicKeyDTO getPublicKey() {
        return jwtService.getPublicKey();
    }
}
