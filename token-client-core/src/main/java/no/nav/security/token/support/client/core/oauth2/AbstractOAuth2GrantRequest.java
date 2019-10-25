package no.nav.security.token.support.client.core.oauth2;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2GrantType;

@AllArgsConstructor
@EqualsAndHashCode
abstract class AbstractOAuth2GrantRequest {

    private final OAuth2GrantType oAuth2GrantType;
    private final ClientProperties clientProperties;

    OAuth2GrantType getGrantType() {
        return oAuth2GrantType;
    }

    ClientProperties getClientProperties() {
        return clientProperties;
    }
}
