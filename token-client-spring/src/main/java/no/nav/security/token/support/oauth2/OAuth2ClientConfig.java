package no.nav.security.token.support.oauth2;

import lombok.Data;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.net.URI;
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
    private Map<String, OAuth2Client> clients = new LinkedHashMap<>();

    public Map<String, OAuth2Client> getClients() {
        return clients;
    }

    @Data
    @Validated
    public static class OAuth2Client {
        @NotNull
        private URI resourceUrl;
        @NotNull
        private URI tokenEndpointUrl;
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
