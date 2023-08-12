package io.github.uptalent.auth.controller;

import io.github.uptalent.auth.jwt.JwtService;
import io.github.uptalent.auth.model.request.AuthLogin;
import io.github.uptalent.auth.model.request.AuthRegister;
import io.github.uptalent.auth.model.response.JwtResponse;
import io.github.uptalent.auth.model.common.PublicKeyDTO;
import io.github.uptalent.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final JwtService jwtService;
    private final AuthService authService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public void register(@Valid @RequestBody AuthRegister authRegister) {
        authService.registerUser(authRegister);
    }

    @PostMapping("/login")
    @ResponseStatus(HttpStatus.CREATED)
    public JwtResponse login(@Valid @RequestBody AuthLogin authLogin) {
        return authService.loginAccount(authLogin);
    }

    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    public void logout(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false)
                           String accessToken) {
        authService.logout(accessToken);
    }

    @GetMapping("/public-key")
    public PublicKeyDTO getPublicKey() {
        return jwtService.getPublicKey();
    }

    @PostMapping("/verify")
    public JwtResponse verifyAccount(@RequestParam String token) {
        return authService.verifyAccount(token);
    }
}
