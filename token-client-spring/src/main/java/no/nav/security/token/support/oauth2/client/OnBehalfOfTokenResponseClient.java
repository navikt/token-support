package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.oauth2.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

public class OnBehalfOfTokenResponseClient extends AbstractOAuth2TokenResponseClient<OnBehalfOfGrantRequest> {

    private static final String REQUESTED_TOKEN_USE_VALUE = "on_behalf_of";
    private final RestTemplate restTemplate;

    public OnBehalfOfTokenResponseClient(RestTemplate restTemplate) {
        super(restTemplate);
        this.restTemplate = restTemplate;
    }

    protected MultiValueMap<String, String> buildFormParameters(OnBehalfOfGrantRequest onBehalfOfGrantRequest) {
        MultiValueMap<String, String> formParameters = new LinkedMultiValueMap<>();
        OAuth2ClientConfig.OAuth2ClientProperties clientProperties = onBehalfOfGrantRequest.getClientProperties();
        if ("client_secret_post".equals(clientProperties.getClientAuthMethod())) {
            formParameters.add(OAuth2ParameterNames.CLIENT_ID, clientProperties.getClientId());
            formParameters.add(OAuth2ParameterNames.CLIENT_SECRET, clientProperties.getClientSecret());
        }
        formParameters.add(OAuth2ParameterNames.GRANT_TYPE, onBehalfOfGrantRequest.getGrantType().getValue());
        formParameters.add(OAuth2ParameterNames.SCOPE, String.join(" ", clientProperties.getScope()));
        formParameters.add(OAuth2ParameterNames.ASSERTION, onBehalfOfGrantRequest.getAssertion());
        formParameters.add(OAuth2ParameterNames.REQUESTED_TOKEN_USE, REQUESTED_TOKEN_USE_VALUE);
        return formParameters;
    }
}
