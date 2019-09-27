package no.nav.security.token.support.oauth2.client;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import no.nav.security.token.support.oauth2.OAuth2ParameterNames;

import java.util.HashMap;
import java.util.Map;

@Getter
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class OAuth2AccessTokenResponse {
    @JsonProperty(OAuth2ParameterNames.ACCESS_TOKEN)
    private String accessToken;
    @JsonProperty(OAuth2ParameterNames.EXPIRES_AT)
    private int expiresAt;
    @JsonAlias({"expires_in", "ext_expires_in"})
    private int expiresIn;
    @JsonAnySetter
    private Map<String, Object> additonalParameters = new HashMap<>();
}
