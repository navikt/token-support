package no.nav.security.token.support.oauth2.client;

import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

class ClientCredentialsTokenClient extends AbstractOAuth2TokenClient<ClientCredentialsGrantRequest> {

    ClientCredentialsTokenClient(RestTemplate restTemplate) {
        super(restTemplate);
    }

    @Override
    protected MultiValueMap<String, String> buildFormParameters(ClientCredentialsGrantRequest grantRequest) {
        return createDefaultFormParameters(grantRequest);
    }
}
