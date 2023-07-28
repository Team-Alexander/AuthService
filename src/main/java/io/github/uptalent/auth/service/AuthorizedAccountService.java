package io.github.uptalent.auth.service;

import io.github.uptalent.auth.jwt.JwtConstants;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Service
public class AuthorizedAccountService {
    private final Set<String> authorizedAccounts;
    private final ScheduledExecutorService scheduler;

    public AuthorizedAccountService() {
        this.authorizedAccounts = ConcurrentHashMap.newKeySet();
        this.scheduler = Executors.newScheduledThreadPool(1);
    }

    public void saveAuthorizedAccountByEmail(String email) {
        authorizedAccounts.add(email);
        scheduler.schedule(() -> authorizedAccounts.remove(email), JwtConstants.EXPIRATION_TIME, TimeUnit.MINUTES);
    }

    public boolean isAuthorizedAccountByEmail(String email) {
        return authorizedAccounts.contains(email);
    }
}
