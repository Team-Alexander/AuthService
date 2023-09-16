package io.github.uptalent.auth.utils;

import io.github.uptalent.auth.model.request.AuthLogin;
import io.github.uptalent.auth.model.request.AuthRegister;
import io.github.uptalent.auth.model.request.TalentRegister;
import io.github.uptalent.auth.model.response.AuthResponse;
import io.github.uptalent.starter.model.response.JwtResponse;

public final class MockModelsUtil {
    private MockModelsUtil() {}

    public static final String BLOCKED_ACCOUNT = "blocked_account:";

    public static AuthLogin generateAuthLogin() {
        return AuthLogin.builder()
                .email("test@email.com")
                .password("password")
                .build();
    }

    public static AuthResponse generateAuthResponse() {
        return AuthResponse.builder()
                .id(1L)
                .name("Test")
                .email("test@email.com")
                .build();
    }

    public static AuthRegister generateAuthRegister() {
        AuthRegister talentRegister = new TalentRegister("firstname", "lastname");

        talentRegister.setEmail("email@gmail.com");
        talentRegister.setPassword("password");

        return talentRegister;
    }

    public static JwtResponse generateJwtResponse() {
        return new JwtResponse("token");
    }
}
