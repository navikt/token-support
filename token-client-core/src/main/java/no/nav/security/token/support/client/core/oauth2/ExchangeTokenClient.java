package no.nav.security.token.support.client.core.oauth2;

import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2ParameterNames;
import no.nav.security.token.support.client.core.http.OAuth2HttpClient;

import java.util.LinkedHashMap;
import java.util.Map;

public class ExchangeTokenClient extends AbstractOAuth2TokenClient<ExchangeGrantRequest> {

    public ExchangeTokenClient(OAuth2HttpClient oAuth2HttpClient) {
        super(oAuth2HttpClient);
    }

    @Override
    protected Map<String, String> formParameters(ExchangeGrantRequest grantRequest) {
        Map<String, String> formParameters = new LinkedHashMap<>();
        ClientProperties.TokenExchangeProperties tokenExchangeProperties = grantRequest.getClientProperties().getTokenExchange();
        formParameters.put(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, tokenExchangeProperties.subjectTokenType());
        formParameters.put(OAuth2ParameterNames.SUBJECT_TOKEN, grantRequest.getSubjectToken());
        formParameters.put(OAuth2ParameterNames.AUDIENCE, tokenExchangeProperties.getAudience());
        if (tokenExchangeProperties.getResource() != null && !tokenExchangeProperties.getResource().isEmpty()) {
            formParameters.put(OAuth2ParameterNames.RESOURCE, tokenExchangeProperties.getResource());
        }
        return formParameters;
    }
}
