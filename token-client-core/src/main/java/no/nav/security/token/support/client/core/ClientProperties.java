package no.nav.security.token.support.client.core;

import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;

import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

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
    private final URI wellKnownUrl;
    private AuthorizationServerMetadata authorizationServerMetadata;
    private ResourceRetriever resourceRetriever;

    public ClientProperties(URI tokenEndpointUrl,
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

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof ClientProperties)) return false;
        final ClientProperties other = (ClientProperties) o;
        if (!other.canEqual((Object) this)) return false;
        final Object this$tokenEndpointUrl = this.getTokenEndpointUrl();
        final Object other$tokenEndpointUrl = other.getTokenEndpointUrl();
        if (this$tokenEndpointUrl == null ? other$tokenEndpointUrl != null : !this$tokenEndpointUrl.equals(other$tokenEndpointUrl))
            return false;
        final Object this$grantType = this.getGrantType();
        final Object other$grantType = other.getGrantType();
        if (this$grantType == null ? other$grantType != null : !this$grantType.equals(other$grantType)) return false;
        final Object this$scope = this.getScope();
        final Object other$scope = other.getScope();
        if (this$scope == null ? other$scope != null : !this$scope.equals(other$scope)) return false;
        final Object this$authentication = this.getAuthentication();
        final Object other$authentication = other.getAuthentication();
        if (this$authentication == null ? other$authentication != null : !this$authentication.equals(other$authentication))
            return false;
        final Object this$resourceUrl = this.getResourceUrl();
        final Object other$resourceUrl = other.getResourceUrl();
        if (this$resourceUrl == null ? other$resourceUrl != null : !this$resourceUrl.equals(other$resourceUrl))
            return false;
        final Object this$tokenExchange = this.getTokenExchange();
        final Object other$tokenExchange = other.getTokenExchange();
        if (this$tokenExchange == null ? other$tokenExchange != null : !this$tokenExchange.equals(other$tokenExchange))
            return false;
        final Object this$wellKnownUrl = this.getWellKnownUrl();
        final Object other$wellKnownUrl = other.getWellKnownUrl();
        if (this$wellKnownUrl == null ? other$wellKnownUrl != null : !this$wellKnownUrl.equals(other$wellKnownUrl))
            return false;
        final Object this$authorizationServerMetadata = this.getAuthorizationServerMetadata();
        final Object other$authorizationServerMetadata = other.getAuthorizationServerMetadata();
        if (this$authorizationServerMetadata == null ? other$authorizationServerMetadata != null : !this$authorizationServerMetadata.equals(other$authorizationServerMetadata))
            return false;
        final Object this$resourceRetriever = this.getResourceRetriever();
        final Object other$resourceRetriever = other.getResourceRetriever();
        if (this$resourceRetriever == null ? other$resourceRetriever != null : !this$resourceRetriever.equals(other$resourceRetriever))
            return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof ClientProperties;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $tokenEndpointUrl = this.getTokenEndpointUrl();
        result = result * PRIME + ($tokenEndpointUrl == null ? 43 : $tokenEndpointUrl.hashCode());
        final Object $grantType = this.getGrantType();
        result = result * PRIME + ($grantType == null ? 43 : $grantType.hashCode());
        final Object $scope = this.getScope();
        result = result * PRIME + ($scope == null ? 43 : $scope.hashCode());
        final Object $authentication = this.getAuthentication();
        result = result * PRIME + ($authentication == null ? 43 : $authentication.hashCode());
        final Object $resourceUrl = this.getResourceUrl();
        result = result * PRIME + ($resourceUrl == null ? 43 : $resourceUrl.hashCode());
        final Object $tokenExchange = this.getTokenExchange();
        result = result * PRIME + ($tokenExchange == null ? 43 : $tokenExchange.hashCode());
        final Object $wellKnownUrl = this.getWellKnownUrl();
        result = result * PRIME + ($wellKnownUrl == null ? 43 : $wellKnownUrl.hashCode());
        final Object $authorizationServerMetadata = this.getAuthorizationServerMetadata();
        result = result * PRIME + ($authorizationServerMetadata == null ? 43 : $authorizationServerMetadata.hashCode());
        final Object $resourceRetriever = this.getResourceRetriever();
        result = result * PRIME + ($resourceRetriever == null ? 43 : $resourceRetriever.hashCode());
        return result;
    }

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

        public boolean equals(final Object o) {
            if (o == this) return true;
            if (!(o instanceof TokenExchangeProperties))
                return false;
            final TokenExchangeProperties other = (TokenExchangeProperties) o;
            if (!other.canEqual((Object) this)) return false;
            final Object this$audience = this.getAudience();
            final Object other$audience = other.getAudience();
            if (this$audience == null ? other$audience != null : !this$audience.equals(other$audience)) return false;
            final Object this$resource = this.getResource();
            final Object other$resource = other.getResource();
            if (this$resource == null ? other$resource != null : !this$resource.equals(other$resource)) return false;
            return true;
        }

        protected boolean canEqual(final Object other) {
            return other instanceof TokenExchangeProperties;
        }

        public int hashCode() {
            final int PRIME = 59;
            int result = 1;
            final Object $audience = this.getAudience();
            result = result * PRIME + ($audience == null ? 43 : $audience.hashCode());
            final Object $resource = this.getResource();
            result = result * PRIME + ($resource == null ? 43 : $resource.hashCode());
            return result;
        }

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

        public ClientProperties build() {
            return new ClientProperties(tokenEndpointUrl, wellKnownUrl, grantType, scope, authentication, resourceUrl, tokenExchange);
        }

        public String toString() {
            return "ClientProperties.ClientPropertiesBuilder(tokenEndpointUrl=" + this.tokenEndpointUrl + ", wellKnownUrl=" + this.wellKnownUrl + ", grantType=" + this.grantType + ", scope=" + this.scope + ", authentication=" + this.authentication + ", resourceUrl=" + this.resourceUrl + ", tokenExchange=" + this.tokenExchange + ")";
        }
    }
}
