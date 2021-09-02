package no.nav.security.token.support.spring.integrationtest;

import static io.restassured.module.mockmvc.RestAssuredMockMvc.given;
import static no.nav.security.token.support.spring.integrationtest.AProtectedRestController.PROTECTED;
import static no.nav.security.token.support.spring.integrationtest.AProtectedRestController.PROTECTED_WITH_CLAIMS;
import static no.nav.security.token.support.spring.integrationtest.AProtectedRestController.PROTECTED_WITH_CLAIMS2;
import static no.nav.security.token.support.spring.integrationtest.AProtectedRestController.PROTECTED_WITH_CLAIMS_ANY_CLAIMS;
import static no.nav.security.token.support.spring.integrationtest.AProtectedRestController.PROTECTED_WITH_MULTIPLE;
import static no.nav.security.token.support.spring.integrationtest.AProtectedRestController.UNPROTECTED;
import static no.nav.security.token.support.test.JwtTokenGenerator.ACR;
import static no.nav.security.token.support.test.JwtTokenGenerator.AUD;
import static no.nav.security.token.support.test.JwtTokenGenerator.createSignedJWT;

import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.servlet.Filter;

import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.setup.ConfigurableMockMvcBuilder;
import org.springframework.test.web.servlet.setup.MockMvcConfigurer;
import org.springframework.web.context.WebApplicationContext;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.TokenRequest;

import io.restassured.module.mockmvc.RestAssuredMockMvc;
import no.nav.security.mock.oauth2.MockOAuth2Server;
import no.nav.security.mock.oauth2.token.OAuth2TokenCallback;
import no.nav.security.token.support.test.JwkGenerator;

@SpringBootTest
@ContextConfiguration(classes = { ProtectedApplication.class, ProtectedApplicationConfig.class })
@ActiveProfiles("test")
class ProtectedRestControllerIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private MockOAuth2Server mockOAuth2Server;

    @BeforeEach
    void initialiseRestAssuredMockMvcWebApplicationContext() {
        Collection<Filter> filterCollection = webApplicationContext.getBeansOfType(Filter.class).values();
        Filter[] filters = filterCollection.toArray(new Filter[0]);
        MockMvcConfigurer mockMvcConfigurer = new MockMvcConfigurer() {
            @Override
            public void afterConfigurerAdded(ConfigurableMockMvcBuilder<?> builder) {
                builder.addFilters(filters);
            }
        };
        RestAssuredMockMvc.webAppContextSetup(webApplicationContext, mockMvcConfigurer);
    }

    @Test
    void unprotectedMethod() {
        given()
                .when()
                .get(UNPROTECTED)
                .then()
                .log().ifValidationFails()
                .statusCode(HttpStatus.OK.value());
    }

    @Test
    void noTokenInRequest() {
        given()
                .when()
                .get(PROTECTED)
                .then()
                .log().ifValidationFails()
                .statusCode(HttpStatus.UNAUTHORIZED.value());

    }

    @Test
    void unparseableTokenInRequest() {
        expectStatusCode(PROTECTED, "unparseable", HttpStatus.UNAUTHORIZED);
    }

    @Test
    void unsignedTokenInRequest() {
        JWT jwt = new PlainJWT(jwtClaimsSetKnownIssuer());
        expectStatusCode(PROTECTED, jwt.serialize(), HttpStatus.UNAUTHORIZED);
    }

    @Test
    void signedTokenInRequestUnknownIssuer() {
        JWT jwt = issueToken("unknown", jwtClaimsSet(AUD));
        expectStatusCode(PROTECTED, jwt.serialize(), HttpStatus.UNAUTHORIZED);
    }

    @Test
    void signedTokenInRequestUnknownAudience() {
        JWT jwt = issueToken("knownissuer", jwtClaimsSet("unknown"));
        expectStatusCode(PROTECTED, jwt.serialize(), HttpStatus.UNAUTHORIZED);
    }

    @Test
    void signedTokenInRequestProtectedWithClaimsMethodMissingRequiredClaims() {
        JWTClaimsSet jwtClaimsSet = defaultJwtClaimsSetBuilder()
                .claim("importantclaim", "vip")
                .build();
        expectStatusCode(PROTECTED_WITH_CLAIMS, issueToken("knownissuer", jwtClaimsSet).serialize(), HttpStatus.UNAUTHORIZED);
    }

    @Test
    void signedTokenInRequestKeyFromUnknownSource() {
        JWTClaimsSet jwtClaimsSet = jwtClaimsSetKnownIssuer();
        JWT jwt = createSignedJWT(JwkGenerator.createJWK(JwkGenerator.DEFAULT_KEYID, JwkGenerator.generateKeyPair()), jwtClaimsSet);
        expectStatusCode(PROTECTED, jwt.serialize(), HttpStatus.UNAUTHORIZED);
    }

    @Test
    void signedTokenInRequestProtectedMethodShouldBeOk() {
        JWT jwt = issueToken("knownissuer", jwtClaimsSetKnownIssuer());
        expectStatusCode(PROTECTED, jwt.serialize(), HttpStatus.OK);
    }

    @Test
    @DisplayName("Token matches one of the configured issuers, including claims")
    void multipleIssuersOneOKIncludingClaims() {
        JWTClaimsSet jwtClaimsSet = defaultJwtClaimsSetBuilder()
                .claim("claim1", "3")
                .claim("claim2", "4")
                .claim("acr", "Level4")
                .build();
        JWT jwt = issueToken("knownissuer", jwtClaimsSet);
        expectStatusCode(PROTECTED_WITH_MULTIPLE, jwt.serialize(), HttpStatus.OK);
    }

    @Test
    @DisplayName("Token matches one of the configured issuers, but not all claims match")
    void multipleIssuersOneIssuerMatchesButClaimsDont() {
        JWT jwt = issueToken("knownissuer", jwtClaimsSetKnownIssuer());
        expectStatusCode(PROTECTED_WITH_MULTIPLE, jwt.serialize(), HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("Token matches none of the configured issuers")
    void multipleIssuersNoIssuerMatches() {
        JWT jwt = issueToken("knownissuer3", jwtClaimsSetKnownIssuer());
        expectStatusCode(PROTECTED_WITH_MULTIPLE, jwt.serialize(), HttpStatus.UNAUTHORIZED);
    }

    @Test
    void signedTokenInRequestProtectedWithClaimsMethodShouldBeOk() {
        JWTClaimsSet jwtClaimsSet = defaultJwtClaimsSetBuilder()
                .claim("importantclaim", "vip")
                .claim("acr", "Level4")
                .build();

        expectStatusCode(PROTECTED_WITH_CLAIMS, issueToken("knownissuer", jwtClaimsSet).serialize(), HttpStatus.OK);

        JWTClaimsSet jwtClaimsSet2 = defaultJwtClaimsSetBuilder()
                .claim("claim1", "1")
                .build();

        expectStatusCode(PROTECTED_WITH_CLAIMS_ANY_CLAIMS, issueToken("knownissuer", jwtClaimsSet2).serialize(), HttpStatus.OK);
    }

    @Test
    void signedTokenInRequestProtectedWithArrayClaimsMethodShouldBeOk() {
        JWTClaimsSet jwtClaimsSet = defaultJwtClaimsSetBuilder()
            .claim("claim1", List.of("1"))
            .build();

        expectStatusCode(PROTECTED_WITH_CLAIMS_ANY_CLAIMS, issueToken("knownissuer", jwtClaimsSet).serialize(), HttpStatus.OK);
    }

    @Test
    void signedTokenInRequestWithoutSubAndAudClaimsShouldBeOk() {
        Date now = new Date();
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("auth_time", now)
                .notBeforeTime(now)
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + TimeUnit.MINUTES.toMillis(1)))
                .build();

        expectStatusCode(PROTECTED_WITH_CLAIMS2, issueToken("knownissuer2", jwtClaimsSet).serialize(), HttpStatus.OK);
    }

    @Test
    void signedTokenInRequestWithoutSubAndAudClaimsShouldBeNotBeOk() {
        Date now = new Date();
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("auth_time", now)
                .notBeforeTime(now)
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + TimeUnit.MINUTES.toMillis(1)))
                .build();

        expectStatusCode(PROTECTED_WITH_CLAIMS, issueToken("knownissuer", jwtClaimsSet).serialize(), HttpStatus.UNAUTHORIZED);
    }

    private static void expectStatusCode(String uri, String token, HttpStatus httpStatus) {
        given()
                .header("Authorization", "Bearer " + token)
                .when()
                .get(uri)
                .then()
                .log().ifValidationFails()
                .statusCode(httpStatus.value());
    }

    private static JWTClaimsSet.Builder defaultJwtClaimsSetBuilder() {
        Date now = new Date();
        return new JWTClaimsSet.Builder()
                .subject("testsub")
                .audience(AUD)
                .jwtID(UUID.randomUUID().toString())
                .claim("auth_time", now)
                .notBeforeTime(now)
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + TimeUnit.MINUTES.toMillis(1)));
    }

    private static JWTClaimsSet jwtClaimsSetKnownIssuer() {
        return jwtClaimsSet(AUD);
    }

    private static JWTClaimsSet jwtClaimsSet(String audience) {
        return buildClaimSet("testsub", audience, ACR, TimeUnit.MINUTES.toMillis(1));
    }

    public static JWTClaimsSet buildClaimSet(String subject, String audience, String authLevel,
            long expiry) {
        Date now = new Date();
        return new JWTClaimsSet.Builder()
                .subject(subject)
                .audience(audience)
                .jwtID(UUID.randomUUID().toString())
                .claim("acr", authLevel)
                .claim("ver", "1.0")
                .claim("nonce", "myNonce")
                .claim("auth_time", now)
                .notBeforeTime(now)
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + expiry)).build();
    }

    private SignedJWT issueToken(String issuerId, JWTClaimsSet jwtClaimsSet) {
        OAuth2TokenCallback callback = new OAuth2TokenCallback() {
            @Override
            public long tokenExpiry() {
                return 30;
            }

            @Override
            public String subject(@NotNull TokenRequest tokenRequest) {
                return jwtClaimsSet.getSubject();
            }

            @NotNull
            @Override
            public String issuerId() {
                return issuerId;
            }

            @Override
            public List<String> audience(@NotNull TokenRequest tokenRequest) {
                return jwtClaimsSet.getAudience();
            }

            @NotNull
            @Override
            public Map<String, Object> addClaims(@NotNull TokenRequest tokenRequest) {
                return jwtClaimsSet.getClaims();
            }
        };
        return mockOAuth2Server.issueToken(issuerId, "client_id", callback);
    }
}
