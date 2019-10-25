package no.nav.security.token.support.client.core.oauth2;

import lombok.*;

import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("unused")
@Getter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OAuth2AccessTokenResponse {

    private String accessToken;
    private int expiresAt;
    private int expiresIn;
    private Map<String, Object> additonalParameters = new HashMap<>();

    //for jackson if it is used for deserialization
    void setAccess_token(String access_token) {
        this.accessToken = access_token;
    }

    void setExpires_at(int expires_at) {
        this.expiresAt = expires_at;
    }

    void setExpires_in(int expires_in) {
        this.expiresIn = expires_in;
    }
}
