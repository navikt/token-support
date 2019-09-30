package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.oauth2.OAuth2ClientConfig;
import no.nav.security.token.support.oauth2.OAuth2GrantType;

public class ClientCredentialsGrantRequest extends AbstractOAuth2GrantRequest {

    public ClientCredentialsGrantRequest(OAuth2ClientConfig.OAuth2Client oAuth2Client) {
        super(OAuth2GrantType.CLIENT_CREDENTIALS, oAuth2Client);
    }
}
