package no.nav.security.token.support.client.core.oauth2;

import no.nav.security.token.support.client.core.http.OAuth2HttpClient;

import java.util.LinkedHashMap;
import java.util.Map;

import static no.nav.security.token.support.client.core.OAuth2ParameterNames.ASSERTION;
import static no.nav.security.token.support.client.core.OAuth2ParameterNames.REQUESTED_TOKEN_USE;

public class OnBehalfOfTokenClient extends AbstractOAuth2TokenClient<OnBehalfOfGrantRequest> {

    private static final String REQUESTED_TOKEN_USE_VALUE = "on_behalf_of";

    public OnBehalfOfTokenClient(OAuth2HttpClient oAuth2HttpClient) {
        super(oAuth2HttpClient);
    }


    @Override
    protected Map<String, String> formParameters(OnBehalfOfGrantRequest grantRequest) {
        Map<String, String> formParameters = new LinkedHashMap<>();
        formParameters.put(ASSERTION, grantRequest.getAssertion());
        formParameters.put(REQUESTED_TOKEN_USE, REQUESTED_TOKEN_USE_VALUE);
        return formParameters;
    }
}
