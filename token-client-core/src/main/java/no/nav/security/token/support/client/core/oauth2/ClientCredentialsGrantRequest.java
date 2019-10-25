package no.nav.security.token.support.client.core.oauth2;

import lombok.EqualsAndHashCode;
import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2GrantType;

@EqualsAndHashCode(callSuper = true)
public class ClientCredentialsGrantRequest extends AbstractOAuth2GrantRequest {

    @SuppressWarnings("WeakerAccess")
    public ClientCredentialsGrantRequest(ClientProperties clientProperties) {
        super(OAuth2GrantType.CLIENT_CREDENTIALS, clientProperties);
    }
}
