package no.nav.security.token.support.client.core.oauth2;

import no.nav.security.token.support.client.core.http.OAuth2HttpClient;

import java.util.Collections;
import java.util.Map;

public class ExchangeTokenClient extends AbstractOAuth2TokenClient<ExchangeGrantRequest> {

    public ExchangeTokenClient(OAuth2HttpClient oAuth2HttpClient) {
        super(oAuth2HttpClient);
    }

    @Override
    protected Map<String, String> formParameters(ExchangeGrantRequest grantRequest) {
        return Collections.emptyMap();
    }
}
