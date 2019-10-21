package no.nav.security.token.support.client.core.http;

import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse;

public interface OAuth2HttpClient {
    OAuth2AccessTokenResponse post(OAuth2HttpRequest oAuth2HttpRequest);
}
