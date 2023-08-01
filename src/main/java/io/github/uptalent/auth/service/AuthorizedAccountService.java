package io.github.uptalent.auth.service;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

import static io.github.uptalent.auth.jwt.JwtConstants.EXPIRATION_TIME;

@Service
public class AuthorizedAccountService {
    private final Cache<String, Boolean> authorizedAccounts;

    public AuthorizedAccountService() {
        authorizedAccounts = CacheBuilder.newBuilder()
                .expireAfterWrite(EXPIRATION_TIME, TimeUnit.MINUTES)
                .build();
    }

    public void saveAuthorizedAccountByEmail(String email) {
        authorizedAccounts.put(email, true);
    }

    public boolean isAuthorizedAccountByEmail(String email) {
        return authorizedAccounts.getIfPresent(email) != null;
    }

    public void evictAuthorizedAccountByEmail(String email) {
        authorizedAccounts.invalidate(email);
    }
}