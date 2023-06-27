package com.uptalent.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PublicKeyDTO {
    private String algorithm;
    private String format;
    private byte[] encoded;
}
