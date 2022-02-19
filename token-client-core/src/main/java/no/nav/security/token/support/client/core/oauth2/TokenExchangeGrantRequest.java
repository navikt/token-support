package no.nav.security.token.support.client.core.oauth2;

import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2GrantType;

import java.util.Objects;

import static no.nav.security.token.support.client.core.OAuth2GrantType.*;

public class TokenExchangeGrantRequest extends AbstractOAuth2GrantRequest {

    private final String subjectToken;
    @SuppressWarnings("WeakerAccess")
    public TokenExchangeGrantRequest(ClientProperties clientProperties, String subjectToken) {
        super(TOKEN_EXCHANGE, clientProperties);
        this.subjectToken = subjectToken;
    }

    public String getSubjectToken(){
        return this.subjectToken;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        TokenExchangeGrantRequest that = (TokenExchangeGrantRequest) o;
        return Objects.equals(subjectToken, that.subjectToken);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), subjectToken);
    }
}
