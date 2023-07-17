package com.uptalent.auth.service;

import com.uptalent.auth.client.AccountClient;
import com.uptalent.auth.jwt.JwtService;
import com.uptalent.auth.model.request.AuthLogin;
import com.uptalent.auth.model.request.AuthRegister;
import com.uptalent.auth.model.response.JwtResponse;
import com.uptalent.auth.model.response.AuthResponse;
import com.uptalent.auth.model.enums.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
    private final JwtService jwtService;
    private final AccountClient accountClient;

    public JwtResponse registerUser(AuthRegister authRegister) {
        AuthResponse authResponse = accountClient.save(authRegister);

        return generateJwt(authResponse);
    }

    public JwtResponse loginUser(AuthLogin authLogin) {
        AuthResponse authResponse = accountClient.login(authLogin);

        return generateJwt(authResponse);
    }

    private JwtResponse generateJwt(AuthResponse authResponse) {
        String token = jwtService.generateToken(authResponse.getId(),
                authResponse.getName(), Role.valueOf(authResponse.getRole()));
        return new JwtResponse(token);
    }
}
