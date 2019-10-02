package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.oauth2.OAuth2ParameterNames;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

class OnBehalfOfTokenResponseClient extends AbstractOAuth2TokenResponseClient<OnBehalfOfGrantRequest> {

    private static final String REQUESTED_TOKEN_USE_VALUE = "on_behalf_of";

    OnBehalfOfTokenResponseClient(RestTemplate restTemplate) {
        super(restTemplate);
    }

    protected MultiValueMap<String, String> buildFormParameters(OnBehalfOfGrantRequest grantRequest) {
        MultiValueMap<String, String> formParameters = createDefaultFormParameters(grantRequest);
        formParameters.add(OAuth2ParameterNames.ASSERTION, grantRequest.getAssertion());
        formParameters.add(OAuth2ParameterNames.REQUESTED_TOKEN_USE, REQUESTED_TOKEN_USE_VALUE);
        return formParameters;
    }
}
