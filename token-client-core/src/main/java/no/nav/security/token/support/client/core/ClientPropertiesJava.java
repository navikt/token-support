package no.nav.security.token.support.client.core;

import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import jakarta.validation.constraints.NotNull;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

public class ClientPropertiesJava {

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
    private final URI wellKnownUrl;
    private AuthorizationServerMetadata authorizationServerMetadata;
    private ResourceRetriever resourceRetriever;

    public
    ClientPropertiesJava(URI tokenEndpointUrl,
                         URI wellKnownUrl,
                         @NotNull OAuth2GrantType grantType,
                         List<String> scope,
                         @NotNull ClientAuthenticationProperties authentication,
                         URI resourceUrl,
                         TokenExchangeProperties tokenExchange
    ) {
        this.wellKnownUrl = wellKnownUrl;

        if(tokenEndpointUrl != null){
            this.tokenEndpointUrl = tokenEndpointUrl;
        } else {
            this.resourceRetriever = new DefaultResourceRetriever();
            this.authorizationServerMetadata = retrieveAuthorizationServerMetadata();
            this.tokenEndpointUrl = this.authorizationServerMetadata.getTokenEndpointURI();
        }
        this.grantType = getSupported(grantType);
        this.scope = Optional.ofNullable(scope).orElse(Collections.emptyList());
        this.authentication = authentication;
        this.resourceUrl = resourceUrl;
        this.tokenExchange = tokenExchange;
    }

    public static ClientPropertiesBuilder builder() {
        return new ClientPropertiesBuilder();
    }

    private AuthorizationServerMetadata retrieveAuthorizationServerMetadata(){
        if (wellKnownUrl == null) {
            throw new OAuth2ClientException("wellKnownUrl cannot be null, please check your configuration.");
        }
        try {
            return AuthorizationServerMetadata.parse(
                resourceRetriever.retrieveResource(wellKnownUrl.toURL()).getContent()
            );
        } catch (ParseException | IOException e) {
            throw new OAuth2ClientException("received exception when retrieving metadata from url " + wellKnownUrl, e);
        }
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

    public @NotNull URI getTokenEndpointUrl() {
        return this.tokenEndpointUrl;
    }

    public @NotNull OAuth2GrantType getGrantType() {
        return this.grantType;
    }

    public List<String> getScope() {
        return this.scope;
    }

    public @NotNull ClientAuthenticationProperties getAuthentication() {
        return this.authentication;
    }

    public URI getResourceUrl() {
        return this.resourceUrl;
    }

    public TokenExchangeProperties getTokenExchange() {
        return this.tokenExchange;
    }

    public URI getWellKnownUrl() {
        return this.wellKnownUrl;
    }

    public AuthorizationServerMetadata getAuthorizationServerMetadata() {
        return this.authorizationServerMetadata;
    }

    public ResourceRetriever getResourceRetriever() {
        return this.resourceRetriever;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ClientPropertiesJava that = (ClientPropertiesJava) o;
        return Objects.equals(tokenEndpointUrl, that.tokenEndpointUrl) &&
            Objects.equals(grantType, that.grantType) &&
            Objects.equals(scope, that.scope) &&
            Objects.equals(authentication, that.authentication) &&
            Objects.equals(resourceUrl, that.resourceUrl) &&
            Objects.equals(tokenExchange, that.tokenExchange) &&
            Objects.equals(wellKnownUrl, that.wellKnownUrl) &&
            Objects.equals(authorizationServerMetadata, that.authorizationServerMetadata) &&
            Objects.equals(resourceRetriever, that.resourceRetriever);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tokenEndpointUrl, grantType, scope, authentication, resourceUrl, tokenExchange, wellKnownUrl, authorizationServerMetadata, resourceRetriever);
    }

    @Override
    public String toString() {
        return "ClientProperties(tokenEndpointUrl=" + this.getTokenEndpointUrl() + ", grantType=" + this.getGrantType() + ", scope=" + this.getScope() + ", authentication=" + this.getAuthentication() + ", resourceUrl=" + this.getResourceUrl() + ", tokenExchange=" + this.getTokenExchange() + ", wellKnownUrl=" + this.getWellKnownUrl() + ", authorizationServerMetadata=" + this.getAuthorizationServerMetadata() + ", resourceRetriever=" + this.getResourceRetriever() + ")";
    }

    public ClientPropertiesBuilder toBuilder() {
        return new ClientPropertiesBuilder().tokenEndpointUrl(this.tokenEndpointUrl).wellKnownUrl(this.wellKnownUrl).grantType(this.grantType).scope(this.scope).authentication(this.authentication).resourceUrl(this.resourceUrl).tokenExchange(this.tokenExchange);
    }

    public static class TokenExchangeProperties {

        @NotNull
        private final String audience;
        private final String resource;

        public TokenExchangeProperties(@NotNull String audience, String resource) {
            this.audience = audience;
            this.resource = resource;
            validateAfterPropertiesSet();
        }

        public static TokenExchangePropertiesBuilder builder() {
            return new TokenExchangePropertiesBuilder();
        }

        private void validateAfterPropertiesSet() {
            Objects.requireNonNull(audience, "audience must be set");
        }

        public String subjectTokenType() {
            return "urn:ietf:params:oauth:token-type:jwt";
        }

        public @NotNull String getAudience() {
            return this.audience;
        }

        public String getResource() {
            return this.resource;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            TokenExchangeProperties that = (TokenExchangeProperties) o;
            return audience.equals(that.audience) && resource.equals(that.resource);
        }

        @Override
        public int hashCode() {
            return Objects.hash(audience, resource);
        }

        @Override
        public String toString() {
            return "ClientProperties.TokenExchangeProperties(audience=" + this.getAudience() + ", resource=" + this.getResource() + ")";
        }

        public TokenExchangePropertiesBuilder toBuilder() {
            return new TokenExchangePropertiesBuilder().audience(this.audience).resource(this.resource);
        }

        public static class TokenExchangePropertiesBuilder {
            private @NotNull String audience;
            private String resource;

            TokenExchangePropertiesBuilder() {
            }

            public TokenExchangePropertiesBuilder audience(@NotNull String audience) {
                this.audience = audience;
                return this;
            }

            public TokenExchangePropertiesBuilder resource(String resource) {
                this.resource = resource;
                return this;
            }

            public TokenExchangeProperties build() {
                return new TokenExchangeProperties(audience, resource);
            }

            @Override
            public String toString() {
                return "ClientProperties.TokenExchangeProperties.TokenExchangePropertiesBuilder(audience=" + this.audience + ", resource=" + this.resource + ")";
            }
        }
    }

    public static class ClientPropertiesBuilder {
        private URI tokenEndpointUrl;
        private URI wellKnownUrl;
        private @NotNull OAuth2GrantType grantType;
        private List<String> scope;
        private @NotNull ClientAuthenticationProperties authentication;
        private URI resourceUrl;
        private TokenExchangeProperties tokenExchange;

        ClientPropertiesBuilder() {
        }

        public ClientPropertiesBuilder tokenEndpointUrl(URI tokenEndpointUrl) {
            this.tokenEndpointUrl = tokenEndpointUrl;
            return this;
        }

        public ClientPropertiesBuilder wellKnownUrl(URI wellKnownUrl) {
            this.wellKnownUrl = wellKnownUrl;
            return this;
        }

        public ClientPropertiesBuilder grantType(@NotNull OAuth2GrantType grantType) {
            this.grantType = grantType;
            return this;
        }

        public ClientPropertiesBuilder scope(List<String> scope) {
            this.scope = scope;
            return this;
        }

        public ClientPropertiesBuilder authentication(@NotNull ClientAuthenticationProperties authentication) {
            this.authentication = authentication;
            return this;
        }

        public ClientPropertiesBuilder resourceUrl(URI resourceUrl) {
            this.resourceUrl = resourceUrl;
            return this;
        }

        public ClientPropertiesBuilder tokenExchange(TokenExchangeProperties tokenExchange) {
            this.tokenExchange = tokenExchange;
            return this;
        }

        public
        ClientPropertiesJava build() {
            return new ClientPropertiesJava(tokenEndpointUrl, wellKnownUrl, grantType, scope, authentication, resourceUrl, tokenExchange);
        }

        @Override
        public String toString() {
            return "ClientProperties.ClientPropertiesBuilder(tokenEndpointUrl=" + this.tokenEndpointUrl + ", wellKnownUrl=" + this.wellKnownUrl + ", grantType=" + this.grantType + ", scope=" + this.scope + ", authentication=" + this.authentication + ", resourceUrl=" + this.resourceUrl + ", tokenExchange=" + this.tokenExchange + ")";
        }
    }
}