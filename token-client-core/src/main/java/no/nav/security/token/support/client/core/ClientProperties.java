package no.nav.security.token.support.client.core;

import lombok.*;

import javax.validation.constraints.NotNull;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

@Getter
@ToString
@EqualsAndHashCode
@Builder(toBuilder = true)
public class ClientProperties {

    private static final List<OAuth2GrantType> GRANT_TYPES = List.of(
        OAuth2GrantType.JWT_BEARER,
        OAuth2GrantType.CLIENT_CREDENTIALS,
        OAuth2GrantType.TOKEN_EXCHANGE
    );

    @NotNull
    private final URI tokenEndpointUrl;
    @NotNull
    private final OAuth2GrantType grantType;
    private final List<String> scope;
    @NotNull
    private final ClientAuthenticationProperties authentication;
    private final URI resourceUrl;
    private final TokenExchangeProperties tokenExchange;

    public ClientProperties(@NotNull URI tokenEndpointUrl,
                            @NotNull OAuth2GrantType grantType,
                            List<String> scope,
                            @NotNull ClientAuthenticationProperties authentication,
                            URI resourceUrl,
                            TokenExchangeProperties tokenExchange
    ) {
        this.tokenEndpointUrl = tokenEndpointUrl;
        this.grantType = getSupported(grantType);
        this.scope = Optional.ofNullable(scope).orElse(Collections.emptyList());
        this.authentication = authentication;
        this.resourceUrl = resourceUrl;
        this.tokenExchange = tokenExchange;
    }

    private static OAuth2GrantType getSupported(OAuth2GrantType oAuth2GrantType) {
        return Optional.ofNullable(oAuth2GrantType)
            .filter(GRANT_TYPES::contains)
            .orElseThrow(unsupported(oAuth2GrantType));
    }

    private static Supplier<IllegalArgumentException> unsupported(OAuth2GrantType oAuth2GrantType) {
        return () -> new IllegalArgumentException(
            String.format("unsupported %s with value %s, must be one of %s",
                OAuth2GrantType.class.getSimpleName(), oAuth2GrantType, GRANT_TYPES));
    }

    @EqualsAndHashCode
    @ToString
    @Getter
    @Setter
    public static class TokenExchangeProperties {

        @NotNull
        private final String audience;
        private final String resource;

        @Builder(toBuilder = true)
        public TokenExchangeProperties(@NotNull String audience, String resource) {
            this.audience = audience;
            this.resource = resource;
            validateAfterPropertiesSet();
        }

        private void validateAfterPropertiesSet() {
            Objects.requireNonNull(audience, "audience must be set");
        }

        public String subjectTokenType() {
            return "urn:ietf:params:oauth:token-type:jwt";
        }
    }
}
