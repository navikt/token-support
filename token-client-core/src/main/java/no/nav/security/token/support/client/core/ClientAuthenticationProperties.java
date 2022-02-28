package no.nav.security.token.support.client.core;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import no.nav.security.token.support.client.core.jwk.JwkFactory;

import javax.validation.constraints.NotNull;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.*;

public class ClientAuthenticationProperties {

    private static final List<ClientAuthenticationMethod> CLIENT_AUTH_METHODS = List.of(
        CLIENT_SECRET_BASIC,
        CLIENT_SECRET_POST,
        PRIVATE_KEY_JWT
    );

    @NotNull
    private final String clientId;
    private final ClientAuthenticationMethod clientAuthMethod;
    private final String clientSecret;
    private final String clientJwk;
    private final RSAKey clientRsaKey;

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

    private static RSAKey loadKey(String clientPrivateKey) {
        if (clientPrivateKey != null) {
            if (clientPrivateKey.startsWith("{")) {
                return JwkFactory.fromJson(clientPrivateKey);
            } else {
                return JwkFactory.fromJsonFile(clientPrivateKey);
            }
        }
        return null;
    }

    private static ClientAuthenticationMethod getSupported(ClientAuthenticationMethod clientAuthMethod) {
        return clientAuthMethod == null ?
            CLIENT_SECRET_BASIC :
            Optional.of(clientAuthMethod)
                .filter(CLIENT_AUTH_METHODS::contains)
                .orElseThrow(() -> new IllegalArgumentException(
                    String.format("unsupported %s with value %s, must be one of %s",
                        ClientAuthenticationMethod.class.getSimpleName(), clientAuthMethod, CLIENT_AUTH_METHODS)));
    }

    public static ClientAuthenticationPropertiesBuilder builder() {
        return new ClientAuthenticationPropertiesBuilder();
    }

    private void validateAfterPropertiesSet() {
        Objects.requireNonNull(clientId, "clientId cannot be null");
        if (CLIENT_SECRET_BASIC.equals(this.clientAuthMethod)) {
            Objects.requireNonNull(clientSecret, "clientSecret cannot be null");
        } else if (CLIENT_SECRET_POST.equals(this.clientAuthMethod)) {
            Objects.requireNonNull(clientSecret, "clientSecret cannot be null");
        } else if (PRIVATE_KEY_JWT.equals(this.clientAuthMethod)) {
            Objects.requireNonNull(clientJwk, "clientPrivateKey must be set");
        }
    }

    public @NotNull String getClientId() {
        return this.clientId;
    }

    public ClientAuthenticationMethod getClientAuthMethod() {
        return this.clientAuthMethod;
    }

    public String getClientSecret() {
        return this.clientSecret;
    }

    public String getClientJwk() {
        return this.clientJwk;
    }

    public RSAKey getClientRsaKey() {
        return this.clientRsaKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        var that = (ClientAuthenticationProperties) o;
        return Objects.equals(clientId, that.clientId)
            && Objects.equals(clientAuthMethod, that.clientAuthMethod)
            && Objects.equals(clientSecret, that.clientSecret)
            && Objects.equals(clientJwk, that.clientJwk)
            && Objects.equals(clientRsaKey, that.clientRsaKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, clientAuthMethod, clientSecret, clientJwk, clientRsaKey);
    }

    @Override
    public String toString() {
        return "ClientAuthenticationProperties(clientId=" + this.getClientId() + ", clientAuthMethod=" + this.getClientAuthMethod() + ", clientSecret=" + this.getClientSecret() + ", clientJwk=" + this.getClientJwk() + ", clientRsaKey=" + this.getClientRsaKey() + ")";
    }

    public ClientAuthenticationPropertiesBuilder toBuilder() {
        return new ClientAuthenticationPropertiesBuilder().clientId(this.clientId).clientAuthMethod(this.clientAuthMethod).clientSecret(this.clientSecret).clientJwk(this.clientJwk);
    }

    public static class ClientAuthenticationPropertiesBuilder {
        private @NotNull String clientId;
        private ClientAuthenticationMethod clientAuthMethod;
        private String clientSecret;
        private String clientJwk;

        ClientAuthenticationPropertiesBuilder() {
        }

        public ClientAuthenticationPropertiesBuilder clientId(@NotNull String clientId) {
            this.clientId = clientId;
            return this;
        }

        public ClientAuthenticationPropertiesBuilder clientAuthMethod(ClientAuthenticationMethod clientAuthMethod) {
            this.clientAuthMethod = clientAuthMethod;
            return this;
        }

        public ClientAuthenticationPropertiesBuilder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        public ClientAuthenticationPropertiesBuilder clientJwk(String clientJwk) {
            this.clientJwk = clientJwk;
            return this;
        }

        public ClientAuthenticationProperties build() {
            return new ClientAuthenticationProperties(clientId, clientAuthMethod, clientSecret, clientJwk);
        }

        @Override
        public String toString() {
            return "ClientAuthenticationProperties.ClientAuthenticationPropertiesBuilder(clientId=" + this.clientId + ", clientAuthMethod=" + this.clientAuthMethod + ", clientSecret=" + this.clientSecret + ", clientJwk=" + this.clientJwk + ")";
        }
    }
}
