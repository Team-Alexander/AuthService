package io.github.uptalent.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uptalent.auth.client.AccountClient;
import io.github.uptalent.auth.controller.AuthController;
import io.github.uptalent.auth.exception.AccountVerifyNotFoundException;
import io.github.uptalent.auth.exception.BlockedAccountException;
import io.github.uptalent.auth.exception.UserAlreadyExistsException;
import io.github.uptalent.auth.jwt.JwtService;
import io.github.uptalent.auth.model.request.AuthLogin;
import io.github.uptalent.auth.model.request.AuthRegister;
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

import java.lang.reflect.Field;

import static io.github.uptalent.auth.utils.MockModelsUtil.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
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

    @Test
    @SneakyThrows
    @DisplayName("should return status code 201 when user registered successfully")
    void shouldReturnStatusCode201_whenUserRegisteredSuccessfully() {
        // Given
        AuthRegister authRegister = generateAuthRegister();

        Field field = AuthService.class.getDeclaredField("accountVerifyTtl");
        field.setAccessible(true);
        field.set(authService, 10000L);

        // When
        var response = mockMvc.perform(MockMvcRequestBuilders.post("/api/v1/auth/register")
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(authRegister)));

        // Then
        response.andExpect(status().isCreated());
    }

    @Test
    @SneakyThrows
    @DisplayName("should return status code 409 when user register with occupied email")
    void shouldReturnStatusCode409_whenUserRegisterWithAlreadyOccupiedEmail() {
        // Given
        AuthRegister authRegister = generateAuthRegister();

        doThrow(UserAlreadyExistsException.class).when(authService).registerUser(any(AuthRegister.class));

        // When
        var response = mockMvc.perform(MockMvcRequestBuilders.post("/api/v1/auth/register")
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(authRegister)));

        // Then
        response.andExpect(status().isConflict());
    }

    @Test
    @SneakyThrows
    @DisplayName("should return status code 400 when user pass incorrect data")
    void shouldReturnStatusCode400_whenUserPassIncorrectData() {
        // Given
        AuthRegister authRegister = generateAuthRegister();

        authRegister.setEmail("errorEmailAddress");

        // When
        var response = mockMvc.perform(MockMvcRequestBuilders.post("/api/v1/auth/register")
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(authRegister)));

        // Then
        response.andExpect(status().isBadRequest());
    }

    @Test
    @SneakyThrows
    @DisplayName("should return status code 200 when user pass existing token")
    void shouldReturnStatusCode200_whenUserPassExistingToken() {
        // Given
        String token = "token";

        // When
        var response = mockMvc.perform(MockMvcRequestBuilders.post("/api/v1/auth/verify")
                .param("token", token)
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk());
    }

    @Test
    @SneakyThrows
    @DisplayName("should return status code 404 when user pass not existing token")
    void shouldReturnStatusCode404_whenUserPassNotExistingToken() {
        // Given
        String token = "token";

        doThrow(AccountVerifyNotFoundException.class).when(authService).verifyAccount(anyString());

        // When
        var response = mockMvc.perform(MockMvcRequestBuilders.post("/api/v1/auth/verify")
                .param("token", token)
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isNotFound());
    }
}
