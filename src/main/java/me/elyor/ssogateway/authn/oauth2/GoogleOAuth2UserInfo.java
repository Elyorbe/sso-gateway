package me.elyor.ssogateway.authn.oauth2;

import java.util.Map;

public class GoogleOAuth2UserInfo {

    private Map<String, Object> attributes;

    public GoogleOAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    public String getId() {
        return (String) attributes.get("sub");
    }

    public String getName() {
        return (String) attributes.get("name");
    }

    public String getEmail() {
        return (String) attributes.get("email");
    }

    public String getPictureUrl() {
        return (String) attributes.get("picture");
    }

}
