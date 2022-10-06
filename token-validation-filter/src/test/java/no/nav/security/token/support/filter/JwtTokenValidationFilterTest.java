package no.nav.security.token.support.filter;

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
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import no.nav.security.token.support.core.JwtTokenConstants;
import no.nav.security.token.support.core.configuration.IssuerProperties;
import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration;
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever;
import no.nav.security.token.support.core.context.TokenValidationContext;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.http.HttpRequest;
import no.nav.security.token.support.core.validation.JwtTokenValidationHandler;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtTokenValidationFilterTest {

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
        final TokenValidationContextHolder ctxHolder = new TestTokenValidationContextHolder();

        JwtTokenValidationFilter filter = createFilterToTest(issuerProps, mockResources, ctxHolder);
        final String jwt = createJWT(issuername, mockResources.keysForIssuer(issuername).toRSAPrivateKey());

        final int[] filterCallCounter = new int[]{0};

        when(servletRequest.getCookies()).thenReturn(new Cookie[]{new Cookie("JSESSIONID", "ABCDEF"), new Cookie(IDTOKENCOOKIENAME, jwt)});
        filter.doFilter(servletRequest, servletResponse,
            mockFilterchainAsserting(issuername, "foobar", ctxHolder, filterCallCounter));

        assertEquals(1, filterCallCounter[0], "doFilter should have been called once");
    }

    @Test
    void testSingleValidIdTokenInHeader() throws IOException, URISyntaxException, ServletException, JOSEException {
        final String anotherIssuer = "anotherIssuer";
        Map<String, IssuerProperties> issuerProps = createIssuerPropertiesMap(anotherIssuer, IDTOKENCOOKIENAME);

        MockResourceRetriever mockResources = new MockResourceRetriever(anotherIssuer);
        final TokenValidationContextHolder ctxHolder = new TestTokenValidationContextHolder();
        JwtTokenValidationFilter filter = createFilterToTest(issuerProps, mockResources, ctxHolder);

        final String jwt = createJWT(anotherIssuer, mockResources.keysForIssuer(anotherIssuer).toRSAPrivateKey());

        final int[] filterCallCounter = new int[]{0};

        when(servletRequest.getCookies()).thenReturn(null);
        when(servletRequest.getHeader(JwtTokenConstants.AUTHORIZATION_HEADER)).thenReturn("Bearer " + jwt);
        filter.doFilter(servletRequest, servletResponse,
            mockFilterchainAsserting(anotherIssuer, "foobar", ctxHolder, filterCallCounter));

        assertEquals(1, filterCallCounter[0], "doFilter should have been called once");
    }

    @Test
    void testTwoValidIdTokensWithDifferentIssuersInHeader() throws IOException, URISyntaxException, ServletException, JOSEException {
        final String issuer1 = "issuer1";
        final String anotherIssuer = "issuerNumberTwo";
        Map<String, IssuerProperties> issuerProps = new HashMap<>();
        issuerProps.putAll(createIssuerPropertiesMap(issuer1, null));
        issuerProps.putAll(createIssuerPropertiesMap(anotherIssuer, null));

        MockResourceRetriever mockResources = new MockResourceRetriever(issuer1, anotherIssuer);
        final TokenValidationContextHolder ctxHolder = new TestTokenValidationContextHolder();
        JwtTokenValidationFilter filter = createFilterToTest(issuerProps, mockResources, ctxHolder);

        final String jwt1 = createJWT(issuer1, mockResources.keysForIssuer(issuer1).toRSAPrivateKey());
        final String jwt2 = createJWT(anotherIssuer, mockResources.keysForIssuer(anotherIssuer).toRSAPrivateKey());

        final int[] filterCallCounter = new int[]{0};

        when(servletRequest.getCookies()).thenReturn(null);
        when(servletRequest.getHeader(JwtTokenConstants.AUTHORIZATION_HEADER)).thenReturn("Bearer " + jwt1 + ",Bearer " + jwt2);
        filter.doFilter(servletRequest, servletResponse,
            mockFilterchainAsserting(new String[]{issuer1, anotherIssuer}, new String[]{"foobar", "foobar"}, ctxHolder, filterCallCounter));

        assertEquals(1, filterCallCounter[0], "doFilter should have been called once");
    }

    @Test
    void testRequestConverterShouldHandleWhenCookiesAreNULL() {
        when(servletRequest.getCookies()).thenReturn(null);
        when(servletRequest.getHeader(JwtTokenConstants.AUTHORIZATION_HEADER)).thenReturn(null);

        HttpRequest req = JwtTokenValidationFilter.fromHttpServletRequest(servletRequest);
        assertNull(req.getCookies());
        assertNull(req.getHeader(JwtTokenConstants.AUTHORIZATION_HEADER));
    }

    @Test
    void testRequestConverterShouldConvertCorrectly() {
        when(servletRequest.getCookies()).thenReturn(new Cookie[]{new Cookie("JSESSIONID", "ABCDEF"), new Cookie("IDTOKEN", "THETOKEN")});
        when(servletRequest.getHeader(JwtTokenConstants.AUTHORIZATION_HEADER)).thenReturn("Bearer eyAAA");

        HttpRequest req = JwtTokenValidationFilter.fromHttpServletRequest(servletRequest);
        assertEquals("JSESSIONID", req.getCookies()[0].getName());
        assertEquals("ABCDEF", req.getCookies()[0].getValue());
        assertEquals("IDTOKEN", req.getCookies()[1].getName());
        assertEquals("THETOKEN", req.getCookies()[1].getValue());
        assertEquals("Bearer eyAAA", req.getHeader(JwtTokenConstants.AUTHORIZATION_HEADER));
    }


    private FilterChain mockFilterchainAsserting(String issuer, String subject, TokenValidationContextHolder ctxHolder, int[] filterCallCounter) {
        return mockFilterchainAsserting(new String[]{issuer}, new String[]{subject}, ctxHolder, filterCallCounter);
    }

    private FilterChain mockFilterchainAsserting(String[] issuers, String[] subjects, TokenValidationContextHolder ctxHolder, int[] filterCallCounter) {
        return (servletRequest, servletResponse) -> {
            // TokenValidationContext is nulled after filter-call, so we check it here:
            filterCallCounter[0]++;
            final TokenValidationContext ctx = ctxHolder.getTokenValidationContext();
            assertTrue(ctx.hasValidToken());
            assertEquals(issuers.length, ctx.getIssuers().size());
            for (int i = 0; i < issuers.length; i++) {
                assertTrue(ctx.hasTokenFor(issuers[i]));
                assertEquals(subjects[i], ctx.getClaims(issuers[i]).getStringClaim("sub"));
            }
        };
    }

    ////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////

    private JwtTokenValidationFilter createFilterToTest(Map<String, IssuerProperties> issuerProps,
                                                        MockResourceRetriever mockResources, TokenValidationContextHolder ctxHolder) {
        MultiIssuerConfiguration conf = new MultiIssuerConfiguration(issuerProps, mockResources);
        JwtTokenValidationHandler jwtTokenValidationHandler = new JwtTokenValidationHandler(conf);
        return new JwtTokenValidationFilter(jwtTokenValidationHandler, ctxHolder);
    }

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

    private static class TestTokenValidationContextHolder implements TokenValidationContextHolder {

        TokenValidationContext tokenValidationContext = new TokenValidationContext(Collections.emptyMap());

        @Override
        public TokenValidationContext getTokenValidationContext() {
            return tokenValidationContext;
        }

        @Override
        public void setTokenValidationContext(TokenValidationContext tokenValidationContext) {
            this.tokenValidationContext = tokenValidationContext;
        }
    }

    class MockResourceRetriever extends ProxyAwareResourceRetriever {

        final String[] mockedIssuers;
        final Map<String, RSAKey> keys = new HashMap<>();

        MockResourceRetriever(String... mockedIssuers) {
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
            return IOUtils.readInputStreamToString(getInputStream("/mockmetadata.json"), StandardCharsets.UTF_8);
        }

        private InputStream getInputStream(String file) {
            return JwtTokenValidationFilterTest.MockResourceRetriever.class.getResourceAsStream(file);
        }

        Resource retrieveJWKS(String issuer) {
            JWKSet set = new JWKSet(keys.get(issuer));
            String content = set.toString();
            return new Resource(content, "application/json");

        }
    }
}
