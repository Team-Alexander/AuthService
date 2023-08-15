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
import io.github.uptalent.auth.model.common.EmailMessageDetailInfo;
import io.github.uptalent.auth.model.hash.AccountVerify;
import io.github.uptalent.auth.model.request.AuthLogin;
import io.github.uptalent.auth.model.request.AuthRegister;
import io.github.uptalent.auth.model.response.JwtResponse;
import io.github.uptalent.auth.model.response.AuthResponse;
import feign.FeignException;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;

import static io.github.uptalent.auth.jwt.JwtConstants.BEARER_PREFIX;

@Service
@RequiredArgsConstructor
public class AuthService {
    private static final String DEFAULT_USER = "user";
    private static final String JWT_BLACKLIST_KEY = "jwt_blacklist:";

    private final JwtService jwtService;
    private final ObjectMapper objectMapper;
    private final AccountClient accountClient;
    private final LoginAttemptService loginAttemptService;
    private final RedisTemplate<String, String> redisTemplate;
    private final AuthorizedAccountService authorizedAccountService;
    private final EmailProducerService emailProducerService;
    private final AccountVerifyService accountVerifyService;

    @Value("${email.verify-account.ttl}")
    private Long accountVerifyTtl;

    public void registerUser(AuthRegister authRegister) {
        String email = authRegister.getEmail().toLowerCase();
        if (accountClient.existsByEmail(email) || accountVerifyService.existsByEmail(email)) {
            throw new UserAlreadyExistsException("Account with email " + email + " already exists");
        }

        String uuid = UUID.randomUUID().toString();
        AccountVerify accountVerify = new AccountVerify(uuid, authRegister, accountVerifyTtl);
        EmailMessageDetailInfo emailMessageDetailInfo = new EmailMessageDetailInfo(uuid,
                DEFAULT_USER,
                email,
                LocalDateTime.now().plusSeconds(accountVerifyTtl));

        accountVerifyService.save(email, accountVerify);
        emailProducerService.sendMessage(emailMessageDetailInfo);
    }

    public JwtResponse verifyAccount(String token) {
        AuthResponse authResponse = accountVerifyService.verifyAccount(token);
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

        String key = JWT_BLACKLIST_KEY + accessToken.toLowerCase();
        redisTemplate.opsForValue().set(key, "");
        redisTemplate.expireAt(key, tokenExpiration);

        authorizedAccountService.evictAuthorizedAccountByEmail(email);
    }

    private JwtResponse generateJwt(AuthResponse authResponse) {
        String token = jwtService.generateToken(authResponse);
        return new JwtResponse(token);
    }

    private void validateLoginAccount(String email) {
        if(accountVerifyService.existsByEmail(email)) {
            throw new BadCredentialsException(String
                    .format("Account with email %s is not verified yet.", email));
        }
        else if (authorizedAccountService.isAuthorizedAccountByEmail(email)) {
            throw new BadCredentialsException(String
                    .format("Account with email %s already authorized.", email));
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
