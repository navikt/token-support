package no.nav.security.token.support.client.core;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import lombok.Data;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

@Data
public class ClientProperties {

    private static final List<OAuth2GrantType> GRANT_TYPES = List.of(
        OAuth2GrantType.JWT_BEARER,
        OAuth2GrantType.CLIENT_CREDENTIALS
    );

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

    public void setGrantType(OAuth2GrantType oAuth2GrantType) {
        setGrantType(Optional.ofNullable(oAuth2GrantType.getValue()).orElse(null));
    }

    public void setGrantType(String value) {
        this.grantType = GRANT_TYPES
            .stream()
            .filter(grant -> grant.getValue().equals(value))
            .findFirst()
            .orElseThrow(unsupported(OAuth2GrantType.class, value));
    }

    public void setClientAuthMethod(ClientAuthenticationMethod clientAuthMethod) {
        setClientAuthMethod(Optional.ofNullable(clientAuthMethod.getValue()).orElse(null));
    }

    @SuppressWarnings("unused")
    public void setClientAuthMethod(String value) {
        this.clientAuthMethod = CLIENT_AUTH_METHODS
            .stream()
            .filter(c -> c.getValue().equals(value))
            .findFirst()
            .orElseThrow(unsupported(ClientAuthenticationMethod.class, value));
    }

    private Supplier<OAuth2ClientException> unsupported(Class<?> clazz, String value) {
        return () -> new OAuth2ClientException(
            String.format("unsupported %s with value %s, must be one of %s",
                clazz.getSimpleName(), value, CLIENT_AUTH_METHODS));
    }
}
