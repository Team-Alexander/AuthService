package io.github.uptalent.auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import io.github.uptalent.auth.client.AccountClient;
import io.github.uptalent.auth.exception.UserAlreadyExistsException;
import io.github.uptalent.auth.exception.UserNotFoundException;
import io.github.uptalent.auth.jwt.JwtService;
import io.github.uptalent.auth.model.request.AuthLogin;
import io.github.uptalent.auth.model.request.AuthRegister;
import io.github.uptalent.auth.model.response.JwtResponse;
import io.github.uptalent.auth.model.response.AuthResponse;
import feign.FeignException;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import java.time.Instant;

import static io.github.uptalent.auth.jwt.JwtConstants.BEARER_PREFIX;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
    private final JwtService jwtService;
    private final ObjectMapper objectMapper;
    private final AccountClient accountClient;
    private final LoginAttemptService loginAttemptService;
    private final RedisTemplate<String, String> redisTemplate;
    private final AuthorizedAccountService authorizedAccountService;

    public JwtResponse registerUser(AuthRegister authRegister) {
        try {
            AuthResponse authResponse = accountClient.save(authRegister);
            return generateJwt(authResponse);
        } catch (FeignException.Conflict e) {
            String extractedMessage = extractMessageFromJson(e.contentUTF8());
            throw new UserAlreadyExistsException(extractedMessage);
        }
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
            String extractedMessage = extractMessageFromJson(e.contentUTF8());
            throw new UserNotFoundException(extractedMessage);
        } catch (FeignException.Unauthorized e) {
            loginAttemptService.incrementAttemptByEmail(authLogin.getEmail());

            String extractedMessage = extractMessageFromJson(e.contentUTF8());
            throw new BadCredentialsException(extractedMessage);
        }
    }

    @SneakyThrows
    public void logout(String accessToken) {
        accessToken = accessToken.substring(BEARER_PREFIX.length());

        JWTClaimsSet claims = JWTParser.parse(accessToken).getJWTClaimsSet();
        Instant tokenExpiration = jwtService.getExpiryFromToken(claims);
        String email = jwtService.getEmailFromToken(claims);

        String key = "blacklist:" + accessToken.toLowerCase();
        redisTemplate.opsForValue().set(key, "");
        redisTemplate.expireAt(key, tokenExpiration);

        authorizedAccountService.evictAuthorizedAccountByEmail(email);
    }

    private JwtResponse generateJwt(AuthResponse authResponse) {
        String token = jwtService.generateToken(authResponse);
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

    private String extractMessageFromJson(String jsonBody) {
        try {
            JsonNode root = objectMapper.readTree(jsonBody);
            return root.path("message").asText();
        } catch (JsonProcessingException e) {
            return jsonBody;
        }
    }
}
