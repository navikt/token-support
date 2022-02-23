package no.nav.security.token.support.core.configuration;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ProxyAwareResourceRetrieverTest {

    @Test
    void testUsePlainTextForHttps() throws IOException {
        ProxyAwareResourceRetriever resourceRetriever = new ProxyAwareResourceRetriever(null, true);
        String scheme = "https://";
        String host = "host.domain.no";
        String pathAndQuery = "/somepath?foo=bar&bar=foo";
        URL url = URI.create(scheme + host + pathAndQuery).toURL();
        assertEquals("http://" + host + ":443" + pathAndQuery,
                resourceRetriever.urlWithPlainTextForHttps(url).toString());
    }

}
