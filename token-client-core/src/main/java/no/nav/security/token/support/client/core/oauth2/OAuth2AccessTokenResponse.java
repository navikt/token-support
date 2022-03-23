package no.nav.security.token.support.client.core.oauth2;

import java.util.HashMap;
import java.util.Map;

public class OAuth2AccessTokenResponse {

    private String accessToken;
    private int expiresAt;
    private int expiresIn;
    private Map<String, Object> additonalParameters = new HashMap<>();

    public OAuth2AccessTokenResponse(String accessToken, int expiresAt, int expiresIn, Map<String, Object> additonalParameters) {
        this.accessToken = accessToken;
        this.expiresAt = expiresAt;
        this.expiresIn = expiresIn;
        this.additonalParameters = additonalParameters;
    }

    public OAuth2AccessTokenResponse() {
    }

    public static OAuth2AccessTokenResponseBuilder builder() {
        return new OAuth2AccessTokenResponseBuilder();
    }

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

    public String getAccessToken() {
        return this.accessToken;
    }

    public String getAccessTokenAsBearer() {
        return "Bearer " + getAccessToken();
    }
    public int getExpiresAt() {
        return this.expiresAt;
    }

    public int getExpiresIn() {
        return this.expiresIn;
    }

    public Map<String, Object> getAdditonalParameters() {
        return this.additonalParameters;
    }

    @Override
    public String toString() {
        return "OAuth2AccessTokenResponse(accessToken=" + this.getAccessToken() + ", expiresAt=" + this.getExpiresAt() + ", expiresIn=" + this.getExpiresIn() + ", additonalParameters=" + this.getAdditonalParameters() + ")";
    }

    public static class OAuth2AccessTokenResponseBuilder {
        private String accessToken;
        private int expiresAt;
        private int expiresIn;
        private Map<String, Object> additonalParameters;

        OAuth2AccessTokenResponseBuilder() {
        }

        public OAuth2AccessTokenResponseBuilder accessToken(String accessToken) {
            this.accessToken = accessToken;
            return this;
        }

        public OAuth2AccessTokenResponseBuilder expiresAt(int expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }

        public OAuth2AccessTokenResponseBuilder expiresIn(int expiresIn) {
            this.expiresIn = expiresIn;
            return this;
        }

        public OAuth2AccessTokenResponseBuilder additonalParameters(Map<String, Object> additonalParameters) {
            this.additonalParameters = additonalParameters;
            return this;
        }

        public OAuth2AccessTokenResponse build() {
            return new OAuth2AccessTokenResponse(accessToken, expiresAt, expiresIn, additonalParameters);
        }

        @Override
        public String toString() {
            return "OAuth2AccessTokenResponse.OAuth2AccessTokenResponseBuilder(accessToken=" + this.accessToken + ", expiresAt=" + this.expiresAt + ", expiresIn=" + this.expiresIn + ", additonalParameters=" + this.additonalParameters + ")";
        }
    }
}
