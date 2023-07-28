package io.github.uptalent.auth.jwt;

import io.github.uptalent.auth.mapper.KeyMapper;
import io.github.uptalent.auth.model.common.PublicKeyDTO;
import io.github.uptalent.auth.model.enums.Role;
import lombok.RequiredArgsConstructor;
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

    public String generateToken(Long id, String name, Role role) {
        var now = Instant.now();
        var claims = JwtClaimsSet.builder()
                .issuer(TOKEN_ISSUER)
                .issuedAt(now)
                .expiresAt(now.plus(EXPIRATION_TIME, MINUTES))
                .subject(String.valueOf(id))
                .id(jti)
                .claim(NAME_CLAIM, name)
                .claim(ROLE_CLAIM, role.name())
                .build();
        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public PublicKeyDTO getPublicKey() {
        return keyMapper.toPublicKeyDTO(publicKey);
    }

}
