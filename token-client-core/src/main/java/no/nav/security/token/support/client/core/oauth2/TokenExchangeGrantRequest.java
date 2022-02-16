package no.nav.security.token.support.client.core.oauth2;

import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2GrantType;

public class TokenExchangeGrantRequest extends AbstractOAuth2GrantRequest {

    private final String subjectToken;
    @SuppressWarnings("WeakerAccess")
    public TokenExchangeGrantRequest(ClientProperties clientProperties, String subjectToken) {
        super(OAuth2GrantType.TOKEN_EXCHANGE, clientProperties);
        this.subjectToken = subjectToken;
    }

    public String getSubjectToken(){
        return this.subjectToken;
    }

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof TokenExchangeGrantRequest)) return false;
        final TokenExchangeGrantRequest other = (TokenExchangeGrantRequest) o;
        if (!other.canEqual((Object) this)) return false;
        if (!super.equals(o)) return false;
        final Object this$subjectToken = this.getSubjectToken();
        final Object other$subjectToken = other.getSubjectToken();
        if (this$subjectToken == null ? other$subjectToken != null : !this$subjectToken.equals(other$subjectToken))
            return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof TokenExchangeGrantRequest;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = super.hashCode();
        final Object $subjectToken = this.getSubjectToken();
        result = result * PRIME + ($subjectToken == null ? 43 : $subjectToken.hashCode());
        return result;
    }
}
