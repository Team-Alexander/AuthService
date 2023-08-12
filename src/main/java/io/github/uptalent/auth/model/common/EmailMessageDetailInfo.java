package io.github.uptalent.auth.model.common;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
public class EmailMessageDetailInfo {
    private String uuid;
    private String username;
    private String email;
    private LocalDateTime expiredDateTime;
}
