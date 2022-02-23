package no.nav.security.token.support.client.core.oauth2;

import no.nav.security.token.support.client.core.http.OAuth2HttpClient;

import java.util.Map;

public class ClientCredentialsTokenClient extends AbstractOAuth2TokenClient<ClientCredentialsGrantRequest> {

    public ClientCredentialsTokenClient(OAuth2HttpClient oAuth2HttpClient) {
        super(oAuth2HttpClient);
    }

    @Override
    protected Map<String, String> formParameters(ClientCredentialsGrantRequest grantRequest) {
        return Map.of();
    }
}
