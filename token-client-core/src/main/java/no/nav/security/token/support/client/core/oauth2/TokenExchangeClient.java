package no.nav.security.token.support.client.core.oauth2;

import no.nav.security.token.support.client.core.http.OAuth2HttpClient;

import java.util.LinkedHashMap;
import java.util.Map;

import static no.nav.security.token.support.client.core.OAuth2ParameterNames.*;

public class TokenExchangeClient extends AbstractOAuth2TokenClient<TokenExchangeGrantRequest> {

    public TokenExchangeClient(OAuth2HttpClient oAuth2HttpClient) {
        super(oAuth2HttpClient);
    }

    @Override
    protected Map<String, String> formParameters(TokenExchangeGrantRequest grantRequest) {
        Map<String, String> formParameters = new LinkedHashMap<>();
        var tokenExchangeProperties = grantRequest.getClientProperties().getTokenExchange();
        formParameters.put(SUBJECT_TOKEN_TYPE, tokenExchangeProperties.subjectTokenType());
        formParameters.put(SUBJECT_TOKEN, grantRequest.getSubjectToken());
        formParameters.put(AUDIENCE, tokenExchangeProperties.getAudience());
        if (tokenExchangeProperties.getResource() != null && !tokenExchangeProperties.getResource().isEmpty()) {
            formParameters.put(RESOURCE, tokenExchangeProperties.getResource());
        }
        return formParameters;
    }
}
