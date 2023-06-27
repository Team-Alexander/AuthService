package com.uptalent.auth.mapper;

import com.uptalent.auth.model.PublicKeyDTO;
import org.mapstruct.Mapper;

import java.security.PublicKey;

@Mapper(componentModel = "spring")
public interface KeyMapper {
    PublicKeyDTO toPublicKeyDTO(PublicKey publicKey);
}
