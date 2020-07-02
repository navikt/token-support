package no.nav.security.token.support.client.core;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import lombok.*;

import javax.validation.constraints.NotNull;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

@EqualsAndHashCode
@ToString
@Getter
@Setter
public class ExchangeProperties {

    private static final List<ClientAuthenticationMethod> CLIENT_AUTH_METHODS = List.of(
        ClientAuthenticationMethod.PRIVATE_KEY_JWT
    );

    private String subjectToken;
    @NotNull
    private final String audience;
    @NotNull
    private final ClientAuthenticationMethod clientAuthMethod;
    private final String resource;

    @Builder(toBuilder = true)
    public ExchangeProperties(@NotNull ClientAuthenticationMethod clientAuthMethod,
                              @NotNull String audience,
                              String resource,
                              String subjectToken) {
        this.clientAuthMethod = getSupported(clientAuthMethod);
        this.audience = audience;
        this.resource = resource;
        this.subjectToken = subjectToken;
        validateAfterPropertiesSet();
    }

    private static ClientAuthenticationMethod getSupported(ClientAuthenticationMethod clientAuthMethod) {
        return clientAuthMethod == null ?
            ClientAuthenticationMethod.PRIVATE_KEY_JWT :
            Optional.of(clientAuthMethod)
                .filter(CLIENT_AUTH_METHODS::contains)
                .orElseThrow(unsupported(clientAuthMethod));
    }

    private void validateAfterPropertiesSet() {
        Objects.requireNonNull(audience, "audience must be set");
    }

    private static Supplier<IllegalArgumentException> unsupported(ClientAuthenticationMethod clientAuthMethod) {
        return () -> new IllegalArgumentException(
            String.format("unsupported %s with value %s, must be one of %s",
                ClientAuthenticationMethod.class.getSimpleName(), clientAuthMethod, CLIENT_AUTH_METHODS));
    }

    public String subjectTokenType() {
        return "urn:ietf:params:oauth:token-type:jwt";
    }

    public void setSubjectToken(String subjectToken) {
        this.subjectToken = subjectToken;
    }
}
