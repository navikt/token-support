package no.nav.security.oidc.filter;

import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import no.nav.security.oidc.configuration.IssuerProperties;
import no.nav.security.oidc.configuration.MultiIssuerConfiguration;
import no.nav.security.oidc.configuration.OIDCResourceRetriever;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

public class TokenRetrieverTest {

    @Mock
    private HttpServletRequest request;

    @Before
    public void setUp(){
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testRetrieveTokensInHeader() throws URISyntaxException, MalformedURLException {
        MultiIssuerConfiguration config = new MultiIssuerConfiguration(createIssuerPropertiesMap("issuer1", "cookie1"), new NoopResourceRetriever());
        String issuer1Token = createJWT("issuer1");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + issuer1Token);
        assertEquals("issuer1", TokenRetriever.retrieveTokens(config, request).get(0).getIssuer());
    }

    @Test
    public void testRetrieveTokensInHeaderIssuerNotConfigured() throws URISyntaxException, MalformedURLException {
        MultiIssuerConfiguration config = new MultiIssuerConfiguration(createIssuerPropertiesMap("issuer1", "cookie1"), new NoopResourceRetriever());
        String issuer1Token = createJWT("issuerNotConfigured");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + issuer1Token);
        assertEquals(0, TokenRetriever.retrieveTokens(config, request).size());
    }

    @Test
    public void testRetrieveTokensInCookie() throws URISyntaxException, MalformedURLException {
        MultiIssuerConfiguration config = new MultiIssuerConfiguration(createIssuerPropertiesMap("issuer1", "cookie1"), new NoopResourceRetriever());
        String issuer1Token = createJWT("issuer1");
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("cookie1",issuer1Token)});
        assertEquals("issuer1", TokenRetriever.retrieveTokens(config, request).get(0).getIssuer());
    }

    @Test
    public void testRetrieveTokensMultipleIssuersWithSameCookieName() throws URISyntaxException, MalformedURLException {
        Map<String, IssuerProperties> issuerPropertiesMap = createIssuerPropertiesMap("issuer1", "cookie1");
        issuerPropertiesMap.putAll(createIssuerPropertiesMap("issuer2", "cookie1"));

        MultiIssuerConfiguration config = new MultiIssuerConfiguration(issuerPropertiesMap, new NoopResourceRetriever());

        String issuer1Token = createJWT("issuer1");
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("cookie1",issuer1Token)});
        assertEquals(1, TokenRetriever.retrieveTokens(config, request).size());
        assertEquals("issuer1", TokenRetriever.retrieveTokens(config, request).get(0).getIssuer());
    }

    private Map<String, IssuerProperties> createIssuerPropertiesMap(String issuer, String cookieName) throws URISyntaxException, MalformedURLException {
        Map<String, IssuerProperties> issuerPropertiesMap = new HashMap<>();
        issuerPropertiesMap.put(issuer, new IssuerProperties(new URI("https://" + issuer).toURL(), Arrays.asList("aud1"), cookieName));
        return issuerPropertiesMap;
    }

    private String createJWT(String issuer){
        Date now = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("foobar").issuer(issuer).notBeforeTime(now).issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600)).build();
        return new PlainJWT(claimsSet).serialize();
    }

    class NoopResourceRetriever extends OIDCResourceRetriever {

        @Override
        public Resource retrieveResource(URL url) throws IOException {
            String content = getContentFromFile();
            content = content.replace("$ISSUER", url.toString());
            return new Resource(content, "application/json");
        }

        private String getContentFromFile() throws IOException {
            return IOUtils.readInputStreamToString( getInputStream("/metadata.json"), Charset.forName("UTF-8"));
        }

        private InputStream getInputStream(String file){
            return NoopResourceRetriever.class.getResourceAsStream(file);
        }
    }
}