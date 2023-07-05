package com.uptalent.auth.service;

import com.uptalent.auth.client.AccountClient;
import com.uptalent.auth.jwt.JwtService;
import com.uptalent.auth.model.request.AuthRegister;
import com.uptalent.auth.model.response.JwtResponse;
import com.uptalent.auth.model.response.AuthResponse;
import com.uptalent.auth.model.enums.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final JwtService jwtService;
    private final AccountClient accountClient;

    public JwtResponse registerUser(AuthRegister authRegister) {
        AuthResponse authResponse = accountClient.save(authRegister);

        String token = jwtService.generateToken(authResponse.getId(),
                authResponse.getName(), Role.valueOf(authResponse.getRole()));
        return new JwtResponse(token);
    }
}
