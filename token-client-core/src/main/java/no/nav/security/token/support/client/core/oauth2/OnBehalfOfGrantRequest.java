package no.nav.security.token.support.client.core.oauth2;

import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2GrantType;

public class OnBehalfOfGrantRequest extends AbstractOAuth2GrantRequest {
    private final String assertion;

    public OnBehalfOfGrantRequest(ClientProperties clientProperties, String assertion) {
        super(OAuth2GrantType.JWT_BEARER, clientProperties);
        this.assertion = assertion;
    }

    String getAssertion() {
        return this.assertion;
    }

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof OnBehalfOfGrantRequest)) return false;
        final OnBehalfOfGrantRequest other = (OnBehalfOfGrantRequest) o;
        if (!other.canEqual((Object) this)) return false;
        if (!super.equals(o)) return false;
        final Object this$assertion = this.getAssertion();
        final Object other$assertion = other.getAssertion();
        if (this$assertion == null ? other$assertion != null : !this$assertion.equals(other$assertion)) return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof OnBehalfOfGrantRequest;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = super.hashCode();
        final Object $assertion = this.getAssertion();
        result = result * PRIME + ($assertion == null ? 43 : $assertion.hashCode());
        return result;
    }
}
