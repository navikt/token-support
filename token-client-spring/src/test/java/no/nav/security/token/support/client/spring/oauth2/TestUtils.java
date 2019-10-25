package no.nav.security.token.support.client.spring.oauth2;

import okhttp3.mockwebserver.MockResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

class TestUtils {

    static MockResponse jsonResponse(String json) {
        return new MockResponse()
            .setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .setBody(json);
    }
}
