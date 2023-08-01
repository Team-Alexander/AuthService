package io.github.uptalent.auth.jwt;

public class JwtConstants {
    public static final long EXPIRATION_TIME = 60; // 60 minutes
    public static final String TOKEN_ISSUER = "UpTalent";
    public static final String ROLE_CLAIM = "role";
    public static final String NAME_CLAIM = "name";
    public static final String EMAIL_CLAIM = "email";
    public static final String BEARER_PREFIX = "Bearer ";
}
