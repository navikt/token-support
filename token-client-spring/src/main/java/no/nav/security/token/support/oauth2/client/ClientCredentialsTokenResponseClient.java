package no.nav.security.token.support.oauth2.client;

import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

class ClientCredentialsTokenResponseClient extends AbstractOAuth2TokenResponseClient<ClientCredentialsGrantRequest> {

    ClientCredentialsTokenResponseClient(RestTemplate restTemplate) {
        super(restTemplate);
    }

    @Override
    protected MultiValueMap<String, String> buildFormParameters(ClientCredentialsGrantRequest grantRequest) {
        return createDefaultFormParameters(grantRequest);
    }
}
