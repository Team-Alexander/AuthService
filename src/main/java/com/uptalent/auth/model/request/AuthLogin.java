package com.uptalent.auth.model.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthLogin {
    @Email
    @NotBlank(message = "Email should not be blank")
    @Size(max = 100, message = "Email must be less than 100 characters")
    private String email;

    @NotBlank(message = "Password should not be blank")
    @Size(min = 6, max = 32, message = "Password must be between 6 and 32 characters")
    private String password;
}
