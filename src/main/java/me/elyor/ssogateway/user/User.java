package me.elyor.ssogateway.user;

import lombok.Builder;
import lombok.Getter;
import me.elyor.ssogateway.authn.common.AuthenticationProvider;
import org.springframework.data.annotation.Id;

import java.time.LocalDateTime;

@Getter
@Builder
public class User {

        @Id
        private String email;
        private String name;
        private AuthenticationProvider authProvider;
        private String oauth2Id;
        private Boolean isLocked;
        private Boolean isEnabled;
        private LocalDateTime lastLoginAt;

}
