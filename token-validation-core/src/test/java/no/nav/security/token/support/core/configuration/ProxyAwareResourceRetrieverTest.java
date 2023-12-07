package no.nav.security.token.support.core.configuration;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.*;

class ProxyAwareResourceRetrieverTest {

    @Test
    void testNoProxy() throws MalformedURLException {
        var retriever = new ProxyAwareResourceRetriever(new URL("http://proxy:8080"));
        assertTrue(retriever.shouldProxy(new URL("http://www.vg.no")));
        assertFalse(retriever.shouldProxy(new URL("http:/www.aetat.no")));
        retriever = new ProxyAwareResourceRetriever();
        assertFalse(retriever.shouldProxy(new URL("http:/www.aetat.no")));
        assertFalse(retriever.shouldProxy(new URL("http://www.vg.no")));

    }
    //@Test
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