package com.uptalent.auth.client;

import com.uptalent.auth.model.request.AuthLogin;
import com.uptalent.auth.model.request.AuthRegister;
import com.uptalent.auth.model.response.AuthResponse;
import io.github.resilience4j.retry.annotation.Retry;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient("account-service")
@Retry(name = "default")
public interface AccountClient {
    @PostMapping("/api/v1/account/save")
    AuthResponse save(@RequestBody AuthRegister authRegister);

    @PostMapping("/api/v1/account/login")
    AuthResponse login(@RequestBody AuthLogin authLogin);
}
