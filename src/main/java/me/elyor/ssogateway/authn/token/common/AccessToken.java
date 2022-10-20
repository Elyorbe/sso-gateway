package me.elyor.ssogateway.authn.token.common;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.util.Date;

@Getter
@Builder
@AllArgsConstructor
public class AccessToken {

    private String value;
    private String type;
    private String principal;
    private Date issuedAt;
    private Date expiresAt;

}
