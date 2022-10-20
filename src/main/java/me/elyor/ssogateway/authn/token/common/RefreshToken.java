package me.elyor.ssogateway.authn.token.common;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Date;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    private String value;
    private String principal;
    private Date issuedAt;
    private Date expiresAt;

}
