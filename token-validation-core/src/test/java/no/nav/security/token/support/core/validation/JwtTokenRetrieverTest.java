package no.nav.security.token.support.core.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import no.nav.security.token.support.core.configuration.IssuerProperties;
import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration;
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever;
import no.nav.security.token.support.core.http.HttpRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

//TODO more tests, including multiple issuers setup, and multiple tokens in one header etc
@ExtendWith(MockitoExtension.class)
class JwtTokenRetrieverTest {

    @Mock
    private HttpRequest request;

    @Test
    void testRetrieveTokensInHeader() throws URISyntaxException, MalformedURLException {
        MultiIssuerConfiguration config = new MultiIssuerConfiguration(createIssuerPropertiesMap("issuer1", "cookie1"),
                new NoopResourceRetriever());
        String issuer1Token = createJWT("issuer1");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + issuer1Token);
        assertEquals("issuer1", JwtTokenRetriever.retrieveUnvalidatedTokens(config, request).get(0).getIssuer());
    }

    @Test
    void testRetrieveTokensInHeaderIssuerNotConfigured() throws URISyntaxException, MalformedURLException {
        MultiIssuerConfiguration config = new MultiIssuerConfiguration(createIssuerPropertiesMap("issuer1", "cookie1"),
                new NoopResourceRetriever());
        String issuer1Token = createJWT("issuerNotConfigured");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + issuer1Token);
        assertEquals(0, JwtTokenRetriever.retrieveUnvalidatedTokens(config, request).size());
    }

    @Test
    void testRetrieveTokensInCookie() throws URISyntaxException, MalformedURLException {
        MultiIssuerConfiguration config = new MultiIssuerConfiguration(createIssuerPropertiesMap("issuer1", "cookie1"),
                new NoopResourceRetriever());
        String issuer1Token = createJWT("issuer1");
        when(request.getCookies()).thenReturn(new Cookie[] { new Cookie("cookie1", issuer1Token) });
        assertEquals("issuer1", JwtTokenRetriever.retrieveUnvalidatedTokens(config, request).get(0).getIssuer());
    }

    @Test
    void testRetrieveTokensMultipleIssuersWithSameCookieName() throws URISyntaxException, MalformedURLException {
        Map<String, IssuerProperties> issuerPropertiesMap = createIssuerPropertiesMap("issuer1", "cookie1");
        issuerPropertiesMap.putAll(createIssuerPropertiesMap("issuer2", "cookie1"));

        MultiIssuerConfiguration config = new MultiIssuerConfiguration(issuerPropertiesMap,
                new NoopResourceRetriever());

        String issuer1Token = createJWT("issuer1");
        when(request.getCookies()).thenReturn(new Cookie[] { new Cookie("cookie1", issuer1Token) });
        assertEquals(1, JwtTokenRetriever.retrieveUnvalidatedTokens(config, request).size());
        assertEquals("issuer1", JwtTokenRetriever.retrieveUnvalidatedTokens(config, request).get(0).getIssuer());
    }

    private Map<String, IssuerProperties> createIssuerPropertiesMap(String issuer, String cookieName)
            throws URISyntaxException, MalformedURLException {
        Map<String, IssuerProperties> issuerPropertiesMap = new HashMap<>();
        issuerPropertiesMap.put(issuer,
                new IssuerProperties(new URI("https://" + issuer).toURL(), Collections.singletonList("aud1"), cookieName));
        return issuerPropertiesMap;
    }

    private String createJWT(String issuer) {
        Date now = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("foobar").issuer(issuer).notBeforeTime(now).issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600)).build();
        return new PlainJWT(claimsSet).serialize();
    }

    class NoopResourceRetriever extends ProxyAwareResourceRetriever {

        @Override
        public Resource retrieveResource(URL url) throws IOException {
            String content = getContentFromFile();
            content = content.replace("$ISSUER", url.toString());
            return new Resource(content, "application/json");
        }

        private String getContentFromFile() throws IOException {
            return IOUtils.readInputStreamToString(getInputStream("/metadata.json"), Charset.forName("UTF-8"));
        }

        private InputStream getInputStream(String file) {
            return NoopResourceRetriever.class.getResourceAsStream(file);
        }
    }

    private class Cookie implements HttpRequest.NameValue {

        private final String name;
        private final String value;

        Cookie(String name, String value) {
            this.name = name;
            this.value = value;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public String getValue() {
            return value;
        }
    }
}
