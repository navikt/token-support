package no.nav.security.spring.oidc.integrationtest;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import io.restassured.module.mockmvc.RestAssuredMockMvc;
import no.nav.security.token.support.core.test.support.JwkGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.setup.ConfigurableMockMvcBuilder;
import org.springframework.test.web.servlet.setup.MockMvcConfigurer;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.Filter;
import java.util.Collection;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static io.restassured.module.mockmvc.RestAssuredMockMvc.given;
import static no.nav.security.spring.oidc.integrationtest.ProtectedRestController.*;
import static no.nav.security.token.support.core.test.support.JwtTokenGenerator.*;

@SpringBootTest
@ContextConfiguration(classes = {ProtectedApplication.class, ProtectedApplicationConfig.class})
@ActiveProfiles("test")
class ProtectedRestControllerIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

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
        JWT jwt = createSignedJWT(jwtClaimsSet("unknown", AUD));
        expectStatusCode(PROTECTED, jwt.serialize(), HttpStatus.UNAUTHORIZED);
    }

    @Test
    void signedTokenInRequestUnknownAudience() {
        JWT jwt = createSignedJWT(jwtClaimsSet(ISS, "unknown"));
        expectStatusCode(PROTECTED, jwt.serialize(), HttpStatus.UNAUTHORIZED);
    }

    @Test
    void signedTokenInRequestProtectedWithClaimsMethodMissingRequiredClaims() {
        JWTClaimsSet jwtClaimsSet = defaultJwtClaimsSetBuilder()
                .claim("importantclaim", "vip")
                .build();
        expectStatusCode(PROTECTED_WITH_CLAIMS, createSignedJWT(jwtClaimsSet).serialize(), HttpStatus.UNAUTHORIZED);
    }

    @Test
    void signedTokenInRequestKeyFromUnknownSource() {
        JWTClaimsSet jwtClaimsSet = jwtClaimsSetKnownIssuer();
        JWT jwt = createSignedJWT(JwkGenerator.createJWK(JwkGenerator.DEFAULT_KEYID, JwkGenerator.generateKeyPair()), jwtClaimsSet);
        expectStatusCode(PROTECTED, jwt.serialize(), HttpStatus.UNAUTHORIZED);
    }


    @Test
    void signedTokenInRequestProtectedMethodShouldBeOk() {
        JWT jwt = createSignedJWT(jwtClaimsSetKnownIssuer());
        expectStatusCode(PROTECTED, jwt.serialize(), HttpStatus.OK);
    }

    @Test
    void signedTokenInRequestProtectedWithClaimsMethodShouldBeOk() {
        JWTClaimsSet jwtClaimsSet = defaultJwtClaimsSetBuilder()
                .claim("importantclaim", "vip")
                .claim("acr", "Level4")
                .build();

        expectStatusCode(PROTECTED_WITH_CLAIMS, createSignedJWT(jwtClaimsSet).serialize(), HttpStatus.OK);

        JWTClaimsSet jwtClaimsSet2 = defaultJwtClaimsSetBuilder()
                .claim("claim1", "1")
                .build();

        expectStatusCode(PROTECTED_WITH_CLAIMS_ANY_CLAIMS, createSignedJWT(jwtClaimsSet2).serialize(), HttpStatus.OK);
    }



    private static void expectStatusCode(String uri, String token, HttpStatus httpStatus){
        given()
                .header("Authorization", "Bearer " + token)
                .when()
                .get(uri)
                .then()
                .log().ifValidationFails()
                .statusCode(httpStatus.value());
    }

    private static JWTClaimsSet.Builder defaultJwtClaimsSetBuilder(){
        Date now = new Date();
        return new JWTClaimsSet.Builder()
                .subject("testsub")
                .issuer(ISS)
                .audience(AUD)
                .jwtID(UUID.randomUUID().toString())
                .claim("auth_time", now)
                .notBeforeTime(now)
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + TimeUnit.MINUTES.toMillis(1)));
    }

    private static JWTClaimsSet jwtClaimsSetKnownIssuer() {
        return jwtClaimsSet(ISS, AUD);
    }

    private static JWTClaimsSet jwtClaimsSet(String issuer, String audience) {
        return buildClaimSet("testsub", issuer, audience, ACR, TimeUnit.MINUTES.toMillis(1));
    }
}
