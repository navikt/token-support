package no.nav.security.token.support.client.core;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.net.URI;
import java.util.List;
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
    private final ExchangeProperties tokenExchange;

    public ClientProperties(@NotNull URI tokenEndpointUrl,
                            @NotNull OAuth2GrantType grantType,
                            List<String> scope,
                            @NotNull ClientAuthenticationProperties authentication,
                            URI resourceUrl,
                            ExchangeProperties exchangeProperties
    ) {
        this.tokenEndpointUrl = tokenEndpointUrl;
        this.grantType = getSupported(grantType);
        this.scope = scope;
        this.authentication = authentication;
        this.resourceUrl = resourceUrl;
        this.tokenExchange = exchangeProperties;
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
}
