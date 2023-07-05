package com.uptalent.auth.client;

import com.uptalent.auth.model.AuthRegister;
import com.uptalent.auth.model.RegisterResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient("account-service")
public interface AccountClient {
    @PostMapping("/api/v1/account/save")
    RegisterResponse save(@RequestBody AuthRegister authRegister);
}
