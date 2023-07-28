package com.uptalent.auth.service;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class LoginAttemptService {
    private static final byte MAX_NUMBER_ATTEMPTS = 5;
    private static final byte ATTEMPT_INCREMENT = 1;
    private static final byte START_NUMBER_ATTEMPTS = 0;
    private static final short MAX_CACHE_SIZE = 1000;
    private static final byte EXPIRED_TIME_IN_MINUTES = 1;
    private final Cache<String, Byte> loginAttemptCache;

    public LoginAttemptService() {
        this.loginAttemptCache = CacheBuilder.newBuilder()
                .expireAfterWrite(EXPIRED_TIME_IN_MINUTES, TimeUnit.MINUTES)
                .maximumSize(MAX_CACHE_SIZE)
                .build();
    }

    public void incrementAttemptByEmail(String email) {
        byte attempts = (byte) (ATTEMPT_INCREMENT + getAttemptsByEmail(email));
        log.info("Attempt {} for email [{}]",  attempts, email);
        loginAttemptCache.put(email, attempts);
    }

    public void evictEmailFromAttempts(String email) {
        log.info("Logged in email [{}]", email);
        loginAttemptCache.invalidate(email);
    }

    public boolean isReachedMaxAttempts(String email) {
        return loginAttemptCache.asMap()
                .getOrDefault(email, START_NUMBER_ATTEMPTS) >= MAX_NUMBER_ATTEMPTS;
    }

    private byte getAttemptsByEmail(String email) {
        return loginAttemptCache.asMap()
                .getOrDefault(email, START_NUMBER_ATTEMPTS);
    }
}
