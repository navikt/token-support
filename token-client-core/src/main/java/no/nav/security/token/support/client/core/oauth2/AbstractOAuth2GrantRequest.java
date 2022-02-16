package no.nav.security.token.support.client.core.oauth2;

import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2GrantType;

abstract class AbstractOAuth2GrantRequest {

    private final OAuth2GrantType oAuth2GrantType;
    private final ClientProperties clientProperties;

    public AbstractOAuth2GrantRequest(OAuth2GrantType oAuth2GrantType, ClientProperties clientProperties) {
        this.oAuth2GrantType = oAuth2GrantType;
        this.clientProperties = clientProperties;
    }

    OAuth2GrantType getGrantType() {
        return oAuth2GrantType;
    }

    ClientProperties getClientProperties() {
        return clientProperties;
    }

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof AbstractOAuth2GrantRequest)) return false;
        final AbstractOAuth2GrantRequest other = (AbstractOAuth2GrantRequest) o;
        if (!other.canEqual((Object) this)) return false;
        final Object this$oAuth2GrantType = this.oAuth2GrantType;
        final Object other$oAuth2GrantType = other.oAuth2GrantType;
        if (this$oAuth2GrantType == null ? other$oAuth2GrantType != null : !this$oAuth2GrantType.equals(other$oAuth2GrantType))
            return false;
        final Object this$clientProperties = this.getClientProperties();
        final Object other$clientProperties = other.getClientProperties();
        if (this$clientProperties == null ? other$clientProperties != null : !this$clientProperties.equals(other$clientProperties))
            return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof AbstractOAuth2GrantRequest;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $oAuth2GrantType = this.oAuth2GrantType;
        result = result * PRIME + ($oAuth2GrantType == null ? 43 : $oAuth2GrantType.hashCode());
        final Object $clientProperties = this.getClientProperties();
        result = result * PRIME + ($clientProperties == null ? 43 : $clientProperties.hashCode());
        return result;
    }
}
