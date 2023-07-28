package io.github.uptalent.auth.model.request;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@JsonTypeInfo(
        use = JsonTypeInfo.Id.NAME,
        property = "type")
@JsonSubTypes({
        @JsonSubTypes.Type(value = TalentRegister.class, name = "talentRegister"),
        @JsonSubTypes.Type(value = SponsorRegister.class, name = "sponsorRegister")
})
@Data
@AllArgsConstructor
@NoArgsConstructor
public abstract class AuthRegister {
    @Email
    @NotBlank(message = "Email should not be blank")
    @Size(max = 100, message = "Email must be less than 100 characters")
    private String email;

    @NotBlank(message = "Password should not be blank")
    @Size(min = 6, max = 32, message = "Password must be between 6 and 32 characters")
    private String password;
}
