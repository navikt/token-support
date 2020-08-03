package no.nav.security.token.support.client.core.oauth2;

import lombok.EqualsAndHashCode;
import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2GrantType;

@EqualsAndHashCode(callSuper = true)
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
}
