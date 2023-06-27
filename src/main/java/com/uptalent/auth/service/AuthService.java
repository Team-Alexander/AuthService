package com.uptalent.auth.service;

import com.uptalent.auth.jwt.JwtService;
import com.uptalent.auth.model.AuthRegister;
import com.uptalent.auth.model.AuthResponse;
import com.uptalent.auth.model.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final JwtService jwtService;

    public AuthResponse registerUser(AuthRegister authRegister) {
        String token = jwtService.generateToken(1L, authRegister.getName(), Role.valueOf(authRegister.getRole()));
        return new AuthResponse(token);
    }
}
