package io.github.uptalent.auth.client;

import io.github.uptalent.auth.model.request.AuthLogin;
import io.github.uptalent.auth.model.request.AuthRegister;
import io.github.uptalent.auth.model.response.AuthResponse;
import io.github.resilience4j.retry.annotation.Retry;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient("account-service")
@Retry(name = "default")
public interface AccountClient {
    @PostMapping("/api/v1/account/save")
    AuthResponse save(@RequestBody AuthRegister authRegister);

    @GetMapping("/api/v1/account")
    boolean existsByEmail(@RequestParam String email);

    @PostMapping("/api/v1/account/login")
    AuthResponse login(@RequestBody AuthLogin authLogin);
}
