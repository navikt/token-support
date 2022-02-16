package no.nav.security.token.support.client.core.oauth2;

import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2GrantType;

public class ClientCredentialsGrantRequest extends AbstractOAuth2GrantRequest {

    @SuppressWarnings("WeakerAccess")
    public ClientCredentialsGrantRequest(ClientProperties clientProperties) {
        super(OAuth2GrantType.CLIENT_CREDENTIALS, clientProperties);
    }

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof ClientCredentialsGrantRequest))
            return false;
        final ClientCredentialsGrantRequest other = (ClientCredentialsGrantRequest) o;
        if (!other.canEqual((Object) this)) return false;
        if (!super.equals(o)) return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof ClientCredentialsGrantRequest;
    }

    public int hashCode() {
        int result = super.hashCode();
        return result;
    }
}
