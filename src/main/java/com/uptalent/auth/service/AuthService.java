package com.uptalent.auth.service;

import com.uptalent.auth.client.AccountClient;
import com.uptalent.auth.jwt.JwtService;
import com.uptalent.auth.model.AuthRegister;
import com.uptalent.auth.model.AuthResponse;
import com.uptalent.auth.model.RegisterResponse;
import com.uptalent.auth.model.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final JwtService jwtService;
    private final AccountClient accountClient;

    public AuthResponse registerUser(AuthRegister authRegister) {
        RegisterResponse registerResponse = accountClient.save(authRegister);

        String token = jwtService.generateToken(registerResponse.getId(),
                registerResponse.getName(), Role.valueOf(registerResponse.getRole()));
        return new AuthResponse(token);
    }
}
