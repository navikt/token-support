package no.nav.security.token.support.client.core.oauth2;

import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2GrantType;

import java.util.Objects;

import static no.nav.security.token.support.client.core.OAuth2GrantType.*;

public class OnBehalfOfGrantRequest extends AbstractOAuth2GrantRequest {
    private final String assertion;

    public OnBehalfOfGrantRequest(ClientProperties clientProperties, String assertion) {
        super(JWT_BEARER, clientProperties);
        this.assertion = assertion;
    }

    String getAssertion() {
        return assertion;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        OnBehalfOfGrantRequest that = (OnBehalfOfGrantRequest) o;
        return Objects.equals(assertion, that.assertion);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), assertion);
    }
}
