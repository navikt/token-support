package no.nav.security.token.support.client.core;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import no.nav.security.token.support.client.core.jwk.JwkFactory;

import javax.validation.constraints.NotNull;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

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
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC :
            Optional.of(clientAuthMethod)
                .filter(CLIENT_AUTH_METHODS::contains)
                .orElseThrow(unsupported(clientAuthMethod));
    }

    public static ClientAuthenticationPropertiesBuilder builder() {
        return new ClientAuthenticationPropertiesBuilder();
    }

    private void validateAfterPropertiesSet() {
        Objects.requireNonNull(clientId, "clientId cannot be null");
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(this.clientAuthMethod)) {
            Objects.requireNonNull(clientSecret, "clientSecret cannot be null");
        } else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(this.clientAuthMethod)) {
            Objects.requireNonNull(clientSecret, "clientSecret cannot be null");
        } else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.equals(this.clientAuthMethod)) {
            Objects.requireNonNull(clientJwk, "clientPrivateKey must be set");
        }
    }

    private static Supplier<IllegalArgumentException> unsupported(ClientAuthenticationMethod clientAuthMethod) {
        return () -> new IllegalArgumentException(
            String.format("unsupported %s with value %s, must be one of %s",
                ClientAuthenticationMethod.class.getSimpleName(), clientAuthMethod, CLIENT_AUTH_METHODS));
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

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof ClientAuthenticationProperties)) return false;
        final ClientAuthenticationProperties other = (ClientAuthenticationProperties) o;
        if (!other.canEqual((Object) this)) return false;
        final Object this$clientId = this.getClientId();
        final Object other$clientId = other.getClientId();
        if (this$clientId == null ? other$clientId != null : !this$clientId.equals(other$clientId)) return false;
        final Object this$clientAuthMethod = this.getClientAuthMethod();
        final Object other$clientAuthMethod = other.getClientAuthMethod();
        if (this$clientAuthMethod == null ? other$clientAuthMethod != null : !this$clientAuthMethod.equals(other$clientAuthMethod))
            return false;
        final Object this$clientSecret = this.getClientSecret();
        final Object other$clientSecret = other.getClientSecret();
        if (this$clientSecret == null ? other$clientSecret != null : !this$clientSecret.equals(other$clientSecret))
            return false;
        final Object this$clientJwk = this.getClientJwk();
        final Object other$clientJwk = other.getClientJwk();
        if (this$clientJwk == null ? other$clientJwk != null : !this$clientJwk.equals(other$clientJwk)) return false;
        final Object this$clientRsaKey = this.getClientRsaKey();
        final Object other$clientRsaKey = other.getClientRsaKey();
        if (this$clientRsaKey == null ? other$clientRsaKey != null : !this$clientRsaKey.equals(other$clientRsaKey))
            return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof ClientAuthenticationProperties;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $clientId = this.getClientId();
        result = result * PRIME + ($clientId == null ? 43 : $clientId.hashCode());
        final Object $clientAuthMethod = this.getClientAuthMethod();
        result = result * PRIME + ($clientAuthMethod == null ? 43 : $clientAuthMethod.hashCode());
        final Object $clientSecret = this.getClientSecret();
        result = result * PRIME + ($clientSecret == null ? 43 : $clientSecret.hashCode());
        final Object $clientJwk = this.getClientJwk();
        result = result * PRIME + ($clientJwk == null ? 43 : $clientJwk.hashCode());
        final Object $clientRsaKey = this.getClientRsaKey();
        result = result * PRIME + ($clientRsaKey == null ? 43 : $clientRsaKey.hashCode());
        return result;
    }

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

        public String toString() {
            return "ClientAuthenticationProperties.ClientAuthenticationPropertiesBuilder(clientId=" + this.clientId + ", clientAuthMethod=" + this.clientAuthMethod + ", clientSecret=" + this.clientSecret + ", clientJwk=" + this.clientJwk + ")";
        }
    }
}
