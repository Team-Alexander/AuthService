package io.github.uptalent.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uptalent.auth.controller.AuthController;
import io.github.uptalent.auth.exception.BlockedAccountException;
import io.github.uptalent.auth.jwt.JwtService;
import io.github.uptalent.auth.model.request.AuthLogin;
import io.github.uptalent.auth.service.AuthService;
import io.github.uptalent.starter.model.response.JwtResponse;
import lombok.SneakyThrows;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureWebMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static io.github.uptalent.auth.utils.MockModelsUtil.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureWebMvc
@AutoConfigureMockMvc(addFilters = false)
@WebMvcTest(AuthController.class)
public class AuthControllerTest {
    @MockBean
    private JwtService jwtService;
    @MockBean
    private AuthService authService;

    @Autowired
    MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @SneakyThrows
    @DisplayName("Log in successfully")
    void loginSuccessfully() {
        AuthLogin authLogin = generateAuthLogin();
        JwtResponse jwtResponse = generateJwtResponse();
        String token = jwtResponse.getJwt();

        when(authService.loginAccount(authLogin)).thenReturn(jwtResponse);

        ResultActions response = mockMvc
                .perform(MockMvcRequestBuilders.post("/api/v1/auth/login")
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authLogin)));

        response
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.jwt").value(token));
    }

    @Test
    @SneakyThrows
    @DisplayName("Log in when account is blocked")
    void loginWhenAccountIsBlocked() {
        AuthLogin authLogin = generateAuthLogin();

        when(authService.loginAccount(authLogin)).thenThrow(BlockedAccountException.class);

        mockMvc.perform(MockMvcRequestBuilders.post("/api/v1/auth/login")
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authLogin)))
                .andExpect(status().isForbidden());
    }

    @Test
    @SneakyThrows
    @DisplayName("Log in when account is not verified/already authorized/max attempts reached/bad credentials")
    void loginWhenBadCredentials() {
        AuthLogin authLogin = generateAuthLogin();

        when(authService.loginAccount(authLogin)).thenThrow(BadCredentialsException.class);

        mockMvc.perform(MockMvcRequestBuilders.post("/api/v1/auth/login")
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authLogin)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @SneakyThrows
    @DisplayName("Log out successfully")
    void logoutSuccessfully() {
        String accessToken = "token";

        mockMvc.perform(MockMvcRequestBuilders.post("/api/v1/auth/logout")
                        .header(HttpHeaders.AUTHORIZATION, accessToken))
                .andExpect(status().isOk());
    }
}
