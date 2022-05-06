package no.nav.security.token.support.client.core.oauth2;

import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2GrantType;

import java.util.Objects;

abstract class AbstractOAuth2GrantRequest {

    private final OAuth2GrantType oAuth2GrantType;
    private final ClientProperties clientProperties;

    protected AbstractOAuth2GrantRequest(OAuth2GrantType oAuth2GrantType, ClientProperties clientProperties) {
        this.oAuth2GrantType = oAuth2GrantType;
        this.clientProperties = clientProperties;
    }

    OAuth2GrantType getGrantType() {
        return oAuth2GrantType;
    }

    ClientProperties getClientProperties() {
        return clientProperties;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AbstractOAuth2GrantRequest that = (AbstractOAuth2GrantRequest) o;
        return Objects.equals(oAuth2GrantType, that.oAuth2GrantType)
            && Objects.equals(clientProperties, that.clientProperties);
    }

    @Override
    public int hashCode() {
        return Objects.hash(oAuth2GrantType, clientProperties);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [oAuth2GrantType=" + oAuth2GrantType + ", clientProperties=" + clientProperties + "]";
    }
}
