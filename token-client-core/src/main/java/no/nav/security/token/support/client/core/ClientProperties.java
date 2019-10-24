package no.nav.security.token.support.client.core;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import lombok.Data;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.net.URI;
import java.util.List;
import java.util.function.Supplier;

@Data
public class ClientProperties {

    private static final List<ClientAuthenticationMethod> CLIENT_AUTH_METHODS = List.of(
        ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
        ClientAuthenticationMethod.CLIENT_SECRET_POST,
        ClientAuthenticationMethod.PRIVATE_KEY_JWT);

    @NotNull
    private URI resourceUrl;
    @NotNull
    private URI tokenEndpointUrl;
    @NotEmpty
    private String clientId;
    @NotEmpty
    private String clientSecret;
    private ClientAuthenticationMethod clientAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
    @NotNull
    private OAuth2GrantType grantType;
    @NotEmpty
    private List<String> scope;

    @SuppressWarnings("unused")
    public void setClientAuthMethod(String value){
        this.clientAuthMethod = CLIENT_AUTH_METHODS
            .stream()
                .filter(c -> c.getValue().equals(value))
                .findFirst()
                .orElseThrow(unsupportedClientAuthMethod(value));
    }

    private Supplier<OAuth2ClientException> unsupportedClientAuthMethod(String value) {
        return () -> new OAuth2ClientException(
            String.format("unsupported ClientAuthenticationMethod with value %s, must be one of %s", value,
                CLIENT_AUTH_METHODS));
    }
}
