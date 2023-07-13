package com.uptalent.auth.model.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class SponsorRegister extends AuthRegister{
    @NotBlank(message = "Full name should not be blank")
    @Size(max = 30, message = "Full name must be less than 30 characters")
    private String fullname;
}