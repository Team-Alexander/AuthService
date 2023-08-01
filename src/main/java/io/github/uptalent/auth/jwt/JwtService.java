package io.github.uptalent.auth.jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import io.github.uptalent.auth.mapper.KeyMapper;
import io.github.uptalent.auth.model.common.PublicKeyDTO;
import io.github.uptalent.auth.model.enums.Role;
import io.github.uptalent.auth.model.response.AuthResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.time.Instant;
import java.util.UUID;

import static io.github.uptalent.auth.jwt.JwtConstants.*;
import static java.time.temporal.ChronoUnit.MINUTES;

@Service
@RequiredArgsConstructor
public class JwtService {
    private final JwtEncoder jwtEncoder;
    private final PublicKey publicKey;
    private final KeyMapper keyMapper;
    private final String jti = UUID.randomUUID().toString();

    public String generateToken(AuthResponse authResponse) {
        var now = Instant.now();
        var claims = JwtClaimsSet.builder()
                .issuer(TOKEN_ISSUER)
                .issuedAt(now)
                .expiresAt(now.plus(EXPIRATION_TIME, MINUTES))
                .subject(String.valueOf(authResponse.getId()))
                .id(jti)
                .claim(NAME_CLAIM, authResponse.getName())
                .claim(EMAIL_CLAIM, authResponse.getEmail())
                .claim(ROLE_CLAIM, authResponse.getRole().name())
                .build();
        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public PublicKeyDTO getPublicKey() {
        return keyMapper.toPublicKeyDTO(publicKey);
    }

    @SneakyThrows
    public Instant getExpiryFromToken(JWTClaimsSet claimsSet) {
        return claimsSet.getExpirationTime().toInstant();
    }

    @SneakyThrows
    public String getEmailFromToken(JWTClaimsSet claimsSet) {
        return claimsSet.getStringClaim(EMAIL_CLAIM);
    }
}
