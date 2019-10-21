package no.nav.security.token.support.client.core;

import lombok.Data;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.net.URI;
import java.util.List;

@Data
public class ClientProperties {
    @NotNull
    private URI resourceUrl;
    @NotNull
    private URI tokenEndpointUrl;
    @NotEmpty
    private String clientId;
    @NotEmpty
    private String clientSecret;
    private String clientAuthMethod = "client_secret_basic";
    @NotNull
    private OAuth2GrantType grantType;
    @NotEmpty
    private List<String> scope;
}
