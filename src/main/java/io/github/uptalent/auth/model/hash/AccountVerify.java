package io.github.uptalent.auth.model.hash;

import io.github.uptalent.auth.model.request.AuthRegister;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@RedisHash(value = "account_verify")
public class AccountVerify {
    @Id
    private String token;
    private AuthRegister account;
    @TimeToLive
    private LocalDateTime ttl;
}
