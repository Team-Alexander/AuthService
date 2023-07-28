package io.github.uptalent.auth.mapper;

import io.github.uptalent.auth.model.common.PublicKeyDTO;
import org.mapstruct.Mapper;

import java.security.PublicKey;

@Mapper(componentModel = "spring")
public interface KeyMapper {
    PublicKeyDTO toPublicKeyDTO(PublicKey publicKey);
}
