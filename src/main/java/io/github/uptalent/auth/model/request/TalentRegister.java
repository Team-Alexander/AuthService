package io.github.uptalent.auth.model.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class TalentRegister extends AuthRegister{
    @NotBlank(message = "Lastname should not be blank")
    @Size(max = 15, message = "Lastname must be less than 15 characters")
    private String firstname;

    @NotBlank(message = "Firstname should not be blank")
    @Size(max = 15, message = "Firstname must be less than 15 characters")
    private String lastname;
}
