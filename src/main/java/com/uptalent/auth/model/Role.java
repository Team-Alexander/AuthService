package com.uptalent.auth.model;

import org.springframework.security.core.GrantedAuthority;

public enum Role implements GrantedAuthority {
    TALENT, SPONSOR, ADMIN;
    private final String roleName = "ROLE_" + name();

    @Override
    public String getAuthority() {
        return roleName;
    }
}