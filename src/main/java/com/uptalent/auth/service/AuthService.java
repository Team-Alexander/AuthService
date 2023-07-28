package com.uptalent.auth.service;

import com.uptalent.auth.client.AccountClient;
import com.uptalent.auth.exception.AccountNotFoundException;
import com.uptalent.auth.jwt.JwtService;
import com.uptalent.auth.model.request.AuthLogin;
import com.uptalent.auth.model.request.AuthRegister;
import com.uptalent.auth.model.response.JwtResponse;
import com.uptalent.auth.model.response.AuthResponse;
import com.uptalent.auth.model.enums.Role;
import feign.FeignException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
    private final JwtService jwtService;
    private final AccountClient accountClient;
    private final LoginAttemptService loginAttemptService;
    private final AuthorizedAccountService authorizedAccountService;

    public JwtResponse registerUser(AuthRegister authRegister) {
        AuthResponse authResponse = accountClient.save(authRegister);

        return generateJwt(authResponse);
    }

    public JwtResponse loginAccount(AuthLogin authLogin) {
        String email = authLogin.getEmail();

        try {
            validateLoginAccount(email);
            AuthResponse authResponse = accountClient.login(authLogin);
            loginAttemptService.evictEmailFromAttempts(email);
            authorizedAccountService.saveAuthorizedAccountByEmail(email);

            return generateJwt(authResponse);
        } catch (FeignException.NotFound e) {
            throw new AccountNotFoundException(e.getMessage());
        } catch (FeignException.Unauthorized e) {
            loginAttemptService.incrementAttemptByEmail(authLogin.getEmail());
            throw new BadCredentialsException(e.getLocalizedMessage());
        }

    }

    private JwtResponse generateJwt(AuthResponse authResponse) {
        String token = jwtService.generateToken(authResponse.getId(),
                authResponse.getName(), Role.valueOf(authResponse.getRole()));
        return new JwtResponse(token);
    }

    private void validateLoginAccount(String email) {
        if (authorizedAccountService.isAuthorizedAccountByEmail(email)) {
            throw new BadCredentialsException(String.format("Account with email %s already authorized.", email));
        } else if (loginAttemptService.isReachedMaxAttempts(email)) {
            throw new BadCredentialsException(String
                    .format("Account with email %s already temporary blocked, try later.", email));
        }
    }

}
