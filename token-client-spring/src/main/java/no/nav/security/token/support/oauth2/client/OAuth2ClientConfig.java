package no.nav.security.token.support.oauth2.client;

import lombok.Builder;
import lombok.Data;
import lombok.ToString;
import no.nav.security.token.support.oauth2.OAuth2GrantType;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@ToString
@Validated
@Configuration
@EnableConfigurationProperties
@ConfigurationProperties("no.nav.security.jwt")
public class OAuth2ClientConfig {

    @NotEmpty
    @Valid
    private Map<String, OAuth2ClientProperties> client = new LinkedHashMap<>();

    @Valid
    public Map<String, OAuth2ClientProperties> getClient() {
        return client;
    }

    @Data
    @Builder
    @Validated
    static class OAuth2ClientProperties {
        @NotEmpty
        private String tokenEndpointUrl;
        @NotEmpty
        private String clientId;
        @NotEmpty
        private String clientSecret;
        private String clientAuthMethod;
        @NotNull
        private OAuth2GrantType grantType;
        @NotEmpty
        private List<String> scope;
    }

}
