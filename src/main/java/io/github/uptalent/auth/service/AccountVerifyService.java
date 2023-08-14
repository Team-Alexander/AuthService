package io.github.uptalent.auth.service;

import io.github.uptalent.auth.client.AccountClient;
import io.github.uptalent.auth.exception.AccountVerifyNotFoundException;
import io.github.uptalent.auth.model.hash.AccountVerify;
import io.github.uptalent.auth.model.response.AuthResponse;
import io.github.uptalent.auth.repository.AccountVerifyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class AccountVerifyService {
    private final AccountVerifyRepository accountVerifyRepository;
    private final RedisTemplate<String, String> redisTemplate;
    private final AccountClient accountClient;
    private static final String EMAIL_ON_VERIFY_KEY = "email_on_verify:";

    @Value("${email.verify-account.ttl}")
    private Long accountVerifyTtl;

    public void save(String email, AccountVerify accountVerify) {
        String key = EMAIL_ON_VERIFY_KEY + email;
        accountVerifyRepository.save(accountVerify);
        redisTemplate.opsForValue().set(key, "");
        redisTemplate.expire(key, accountVerifyTtl, TimeUnit.SECONDS);
    }


    public void delete(String token, String email) {
        accountVerifyRepository.deleteById(token);
        redisTemplate.delete(EMAIL_ON_VERIFY_KEY + email);
    }

    public boolean existsByEmail(String email) {
        String key = EMAIL_ON_VERIFY_KEY + email;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    public AuthResponse verifyAccount(String token) {
        AccountVerify accountVerify = accountVerifyRepository.findById(token)
                .orElseThrow(AccountVerifyNotFoundException::new);
        AuthResponse authResponse = accountClient.save(accountVerify.getAccount());

        delete(token, accountVerify.getAccount().getEmail());
        return authResponse;
    }
}
