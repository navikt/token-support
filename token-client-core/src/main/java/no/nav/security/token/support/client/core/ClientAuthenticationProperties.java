package no.nav.security.token.support.client.core;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import lombok.*;
import no.nav.security.token.support.client.core.jwk.JwkFactory;

import javax.validation.constraints.NotNull;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

@EqualsAndHashCode
@ToString
@Getter
public class ClientAuthenticationProperties {

    private static final List<ClientAuthenticationMethod> CLIENT_AUTH_METHODS = List.of(
        ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
        ClientAuthenticationMethod.CLIENT_SECRET_POST,
        ClientAuthenticationMethod.PRIVATE_KEY_JWT
    );

    @NotNull
    private final String clientId;
    private final ClientAuthenticationMethod clientAuthMethod;
    private final String clientSecret;
    @Getter(AccessLevel.NONE)
    private final String clientJwk;
    private final RSAKey clientRsaKey;

    @Builder(toBuilder = true)
    public ClientAuthenticationProperties(@NotNull String clientId,
                                          ClientAuthenticationMethod clientAuthMethod,
                                          String clientSecret,
                                          String clientJwk) {
        this.clientId = clientId;
        this.clientAuthMethod = getSupported(clientAuthMethod);
        this.clientSecret = clientSecret;
        this.clientJwk = clientJwk;
        this.clientRsaKey = loadKey(clientJwk);
        validateAfterPropertiesSet();
    }

    private static RSAKey loadKey(String clientPrivateKey){
        return Optional.ofNullable(clientPrivateKey)
            .map(JwkFactory::fromJsonFile)
            .orElse(null);
    }

    private static ClientAuthenticationMethod getSupported(ClientAuthenticationMethod clientAuthMethod){
        return clientAuthMethod == null ?
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC :
            Optional.of(clientAuthMethod)
            .filter(CLIENT_AUTH_METHODS::contains)
            .orElseThrow(unsupported(clientAuthMethod));
    }

    private void validateAfterPropertiesSet(){
        Objects.requireNonNull(clientId, "clientId cannot be null");
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(this.clientAuthMethod)){
            Objects.requireNonNull(clientSecret, "clientSecret cannot be null");
        } else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(this.clientAuthMethod)){
            Objects.requireNonNull(clientSecret, "clientSecret cannot be null");
        } else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.equals(this.clientAuthMethod)){
            Objects.requireNonNull(clientJwk, "clientPrivateKey must be set");
        }
    }

    private static Supplier<IllegalArgumentException> unsupported(ClientAuthenticationMethod clientAuthMethod) {
        return () -> new IllegalArgumentException(
            String.format("unsupported %s with value %s, must be one of %s",
                ClientAuthenticationMethod.class.getSimpleName(), clientAuthMethod, CLIENT_AUTH_METHODS));
    }
}
