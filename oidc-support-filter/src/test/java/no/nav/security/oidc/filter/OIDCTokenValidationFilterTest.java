package no.nav.security.oidc.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import no.nav.security.oidc.OIDCConstants;
import no.nav.security.oidc.configuration.IssuerProperties;
import no.nav.security.oidc.configuration.MultiIssuerConfiguration;
import no.nav.security.oidc.configuration.OIDCResourceRetriever;
import no.nav.security.oidc.context.OIDCRequestContextHolder;
import no.nav.security.oidc.context.OIDCValidationContext;
import no.nav.security.oidc.http.TokenRetriever;

@ExtendWith(MockitoExtension.class)
class OIDCTokenValidationFilterTest {

    private static final String KEYID = "myKeyId";
    private static final String AUDIENCE = "aud1";
    private static final String IDTOKENCOOKIENAME = "idtokencookie";

    @Mock
    private HttpServletRequest servletRequest;

    @Mock
    private HttpServletResponse servletResponse;

    @Test
    void testSingleValidIdTokenInCookie() throws IOException, URISyntaxException, ServletException, JOSEException {
        final String issuername = "myissuer";
        Map<String, IssuerProperties> issuerProps = createIssuerPropertiesMap(issuername, IDTOKENCOOKIENAME);

        MockResourceRetriever mockResources = new MockResourceRetriever(issuername);
        MultiIssuerConfiguration conf = new MultiIssuerConfiguration(issuerProps, mockResources);
        final OIDCRequestContextHolder ctxHolder = new TestOIDCRequestContextHolder();
        OIDCTokenValidationFilter filter = new OIDCTokenValidationFilter(conf, ctxHolder);

        final String jwt = createJWT(issuername, mockResources.keysForIssuer(issuername).toRSAPrivateKey());

        final int[] filterCallCounter = new int[]{0};

        when(servletRequest.getCookies()).thenReturn(new Cookie[] { new Cookie("JSESSIONID", "ABCDEF"), new Cookie(IDTOKENCOOKIENAME, jwt)});
        filter.doFilter(servletRequest, servletResponse,
                mockFilterchainAsserting(issuername, "foobar", ctxHolder, filterCallCounter));

        assertEquals(1,filterCallCounter[0], "doFilter should have been called once");
    }

    @Test
    void testSingleValidIdTokenInHeader() throws IOException, URISyntaxException, ServletException, JOSEException {
        final String anotherIssuer = "anotherIssuer";
        Map<String, IssuerProperties> issuerProps = createIssuerPropertiesMap(anotherIssuer, IDTOKENCOOKIENAME);

        MockResourceRetriever mockResources = new MockResourceRetriever(anotherIssuer);
        MultiIssuerConfiguration conf = new MultiIssuerConfiguration(issuerProps, mockResources);
        final OIDCRequestContextHolder ctxHolder = new TestOIDCRequestContextHolder();
        OIDCTokenValidationFilter filter = new OIDCTokenValidationFilter(conf, ctxHolder);

        final String jwt = createJWT(anotherIssuer, mockResources.keysForIssuer(anotherIssuer).toRSAPrivateKey());

        final int[] filterCallCounter = new int[]{0};

        when(servletRequest.getCookies()).thenReturn(null);
        when(servletRequest.getHeader(OIDCConstants.AUTHORIZATION_HEADER)).thenReturn("Bearer " + jwt);
        filter.doFilter(servletRequest, servletResponse,
                mockFilterchainAsserting(anotherIssuer, "foobar", ctxHolder, filterCallCounter));

        assertEquals(1,filterCallCounter[0], "doFilter should have been called once");
    }

    @Test
    void testTwoValidIdTokensWithDifferentIssuersInHeader() throws IOException, URISyntaxException, ServletException, JOSEException {
        final String issuer1 = "issuer1";
        final String anotherIssuer = "issuerNumberTwo";
        Map<String, IssuerProperties> issuerProps = new HashMap<>();
        issuerProps.putAll(createIssuerPropertiesMap(issuer1, null));
        issuerProps.putAll(createIssuerPropertiesMap(anotherIssuer, null));

        MockResourceRetriever mockResources = new MockResourceRetriever(issuer1, anotherIssuer);
        MultiIssuerConfiguration conf = new MultiIssuerConfiguration(issuerProps, mockResources);
        final OIDCRequestContextHolder ctxHolder = new TestOIDCRequestContextHolder();
        OIDCTokenValidationFilter filter = new OIDCTokenValidationFilter(conf, ctxHolder);

        final String jwt1 = createJWT(issuer1, mockResources.keysForIssuer(issuer1).toRSAPrivateKey());
        final String jwt2 = createJWT(anotherIssuer, mockResources.keysForIssuer(anotherIssuer).toRSAPrivateKey());

        final int[] filterCallCounter = new int[]{0};

        when(servletRequest.getCookies()).thenReturn(null);
        when(servletRequest.getHeader(OIDCConstants.AUTHORIZATION_HEADER)).thenReturn("Bearer " + jwt1 + ",Bearer " + jwt2);
        filter.doFilter(servletRequest, servletResponse,
                mockFilterchainAsserting(new String[] {issuer1, anotherIssuer}, new String[] {"foobar", "foobar"}, ctxHolder, filterCallCounter));

        assertEquals(1,filterCallCounter[0], "doFilter should have been called once");
    }

    @Test
    void testRequestConverterShouldHandleWhenCookiesAreNULL() {
        when(servletRequest.getCookies()).thenReturn(null);
        when(servletRequest.getHeader(OIDCConstants.AUTHORIZATION_HEADER)).thenReturn(null);

        TokenRetriever.HttpRequest req = OIDCTokenValidationFilter.fromHttpServletRequest(servletRequest);
        assertNull(req.getCookies());
        assertNull(req.getHeader(OIDCConstants.AUTHORIZATION_HEADER));
    }

    @Test
    void testRequestConverterShouldConvertCorrectly() {
        when(servletRequest.getCookies()).thenReturn(new Cookie[] {new Cookie("JSESSIONID", "ABCDEF"), new Cookie("IDTOKEN", "THETOKEN")});
        when(servletRequest.getHeader(OIDCConstants.AUTHORIZATION_HEADER)).thenReturn("Bearer eyAAA");

        TokenRetriever.HttpRequest req = OIDCTokenValidationFilter.fromHttpServletRequest(servletRequest);
        assertEquals("JSESSIONID", req.getCookies()[0].getName());
        assertEquals("ABCDEF", req.getCookies()[0].getValue());
        assertEquals("IDTOKEN", req.getCookies()[1].getName());
        assertEquals("THETOKEN", req.getCookies()[1].getValue());
        assertEquals("Bearer eyAAA", req.getHeader(OIDCConstants.AUTHORIZATION_HEADER));
    }


    private FilterChain mockFilterchainAsserting(String issuer, String subject, OIDCRequestContextHolder ctxHolder, int[] filterCallCounter) {
        return mockFilterchainAsserting(new String[] { issuer }, new String[] { subject }, ctxHolder, filterCallCounter);
    }

    private FilterChain mockFilterchainAsserting(String[] issuers, String[] subjects, OIDCRequestContextHolder ctxHolder, int[] filterCallCounter) {
        return (servletRequest, servletResponse) -> {
            // OIDCValidationContext is nulled after filter-call, so we check it here:
            filterCallCounter[0]++;
            final OIDCValidationContext ctx = ctxHolder.getOIDCValidationContext();
            assertTrue(ctx.hasValidToken());
            assertEquals(issuers.length, ctx.getIssuers().size());
            for (int i = 0; i < issuers.length; i++) {
                assertTrue(ctx.hasTokenFor(issuers[i]));
                assertEquals(subjects[i], ctx.getClaims(issuers[i]).get("sub"));
            }
        };
    }

    ////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////

    private Map<String, IssuerProperties> createIssuerPropertiesMap(String issuer, String cookieName)
            throws URISyntaxException, MalformedURLException {
        Map<String, IssuerProperties> issuerPropertiesMap = new HashMap<>();
        issuerPropertiesMap.put(issuer,
                new IssuerProperties(new URI("https://" + issuer).toURL(), Collections.singletonList(AUDIENCE), cookieName));
        return issuerPropertiesMap;
    }

    private String createJWT(String issuer, RSAPrivateKey signingKey) throws JOSEException {
        Date now = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("foobar").issuer(issuer).audience(AUDIENCE).notBeforeTime(now).issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600)).build();

        JWSSigner signer = new RSASSASigner(signingKey);
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.RS256, null, null, null, null, null, null, null, null, null, KEYID, null, null), claimsSet);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    private static class TestOIDCRequestContextHolder implements OIDCRequestContextHolder {

        Map<String, Object> attrs = new HashMap<>();
        OIDCValidationContext oidcValidationContext = new OIDCValidationContext();

        @Override
        public Object getRequestAttribute(String name) {
            return attrs.get("name");
        }

        @Override
        public void setRequestAttribute(String name, Object value) {
            attrs.put(name, value);
        }

        @Override
        public OIDCValidationContext getOIDCValidationContext() {
            return oidcValidationContext;
        }

        @Override
        public void setOIDCValidationContext(OIDCValidationContext oidcValidationContext) {
            this.oidcValidationContext = oidcValidationContext;
        }
    }

    class MockResourceRetriever extends OIDCResourceRetriever {

        final String[] mockedIssuers;
        final Map<String, RSAKey> keys = new HashMap<>();

        MockResourceRetriever(String ... mockedIssuers) {
            this.mockedIssuers = mockedIssuers;
            for (String iss : mockedIssuers) {
                keys.put(iss, genkey());
            }
        }

        RSAKey keysForIssuer(String issuer) {
            return keys.get(issuer);
        }

        private RSAKey genkey() {
            try {
                KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048);
                KeyPair keyPair = gen.generateKeyPair();
                return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                        .privateKey((RSAPrivateKey) keyPair.getPrivate())
                        .keyID(KEYID).build();
            } catch (NoSuchAlgorithmException nsae) {
                throw new RuntimeException(nsae);
            }
        }

        @Override
        public Resource retrieveResource(URL url) throws IOException {
            final String jkwsPrefix = "http://jwks";
            if (url.toString().startsWith(jkwsPrefix)) {
                return retrieveJWKS(url.toString().substring(jkwsPrefix.length()));
            } else if (Arrays.binarySearch(mockedIssuers, url.getHost()) >= 0) {
                final String issuer = url.getHost();
                String content = getContentFromFile();
                content = content.replace("$ISSUER", issuer);
                content = content.replace(jkwsPrefix, jkwsPrefix + issuer);
                return new Resource(content, "application/json");
            }
            throw new RuntimeException("dont know about issuer " + url);
        }

        private String getContentFromFile() throws IOException {
            return IOUtils.readInputStreamToString(getInputStream("/mockmetadata.json"), Charset.forName("UTF-8"));
        }

        private InputStream getInputStream(String file) {
            return OIDCTokenValidationFilterTest.MockResourceRetriever.class.getResourceAsStream(file);
        }

        Resource retrieveJWKS(String issuer) {
            JWKSet set = new JWKSet(keys.get(issuer));
            String content = set.toString();
            System.out.println(content);
            return new Resource(content, "application/json");

        }
    }
}
