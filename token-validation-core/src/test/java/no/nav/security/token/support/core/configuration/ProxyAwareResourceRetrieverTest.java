package no.nav.security.token.support.core.configuration;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import org.junit.jupiter.api.Test;

public class ProxyAwareResourceRetrieverTest {

    @Test
    public void testUsePlainTextForHttps() throws MalformedURLException, URISyntaxException {
        ProxyAwareResourceRetriever resourceRetriever = new ProxyAwareResourceRetriever(null, true);
        String scheme = "https://";
        String host = "host.domain.no";
        String pathAndQuery = "/somepath?foo=bar&bar=foo";
        URL url = URI.create(scheme + host + pathAndQuery).toURL();
        assertEquals("http://" + host + ":443" + pathAndQuery,
                resourceRetriever.urlWithPlainTextForHttps(url).toString());
    }

}
