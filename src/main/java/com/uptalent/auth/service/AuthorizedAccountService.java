package com.uptalent.auth.service;

import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static com.uptalent.auth.jwt.JwtConstants.EXPIRATION_TIME;

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
        scheduler.schedule(() -> authorizedAccounts.remove(email), EXPIRATION_TIME, TimeUnit.MINUTES);
    }

    public boolean isAuthorizedAccountByEmail(String email) {
        return authorizedAccounts.contains(email);
    }
}
