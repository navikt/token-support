package no.nav.security.spring.oidc.integrationtest;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import io.restassured.module.mockmvc.RestAssuredMockMvc;
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
import java.util.concurrent.TimeUnit;

import static io.restassured.module.mockmvc.RestAssuredMockMvc.given;
import static no.nav.security.oidc.test.support.JwtTokenGenerator.*;

@SpringBootTest
@ContextConfiguration(classes = {ProtectedApplication.class, ProtectedApplicationConfig.class})
@ActiveProfiles("test")
public class ProtectedRestControllerIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @BeforeEach
    void initialiseRestAssuredMockMvcWebApplicationContext() {
        Collection<Filter> filterCollection = webApplicationContext.getBeansOfType(Filter.class).values();
        Filter[] filters = filterCollection.toArray(new Filter[filterCollection.size()]);
        MockMvcConfigurer mockMvcConfigurer = new MockMvcConfigurer() {
            @Override
            public void afterConfigurerAdded(ConfigurableMockMvcBuilder<?> builder) {
                builder.addFilters(filters);
            }
        };
        RestAssuredMockMvc.webAppContextSetup(webApplicationContext, mockMvcConfigurer);
    }

    @Test
    void noTokenInRequest() {
        given()
                .when()
                .get("/protected")
                .then()
                .log().ifValidationFails()
                .statusCode(HttpStatus.UNAUTHORIZED.value());

    }

    @Test
    void unparseableTokenInRequest() {
        given()
                .header("Authorization", "Bearer 123")
                .when()
                .get("/protected")
                .then()
                .log().ifValidationFails()
                .statusCode(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    void unsignedTokenInRequest() {
        JWT jwt = new PlainJWT(jwtClaimsSetKnownIssuer());
        given()
                .header("Authorization", "Bearer " + jwt.serialize())
                .when()
                .get("/protected")
                .then()
                .log().ifValidationFails()
                .statusCode(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    void signedTokenInRequestUnknownIssuer() {
        JWT jwt = createSignedJWT(jwtClaimsSet("unknown", AUD));
        given()
                .header("Authorization", "Bearer " + jwt.serialize())
                .when()
                .get("/protected")
                .then()
                .log().ifValidationFails()
                .statusCode(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    void signedTokenInRequestUnknownAudience() {
        JWT jwt = createSignedJWT(jwtClaimsSet(ISS, "unknown"));
        given()
                .header("Authorization", "Bearer " + jwt.serialize())
                .when()
                .get("/protected")
                .then()
                .log().ifValidationFails()
                .statusCode(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    void signedTokenInRequestAllGood() {
        JWT jwt = createSignedJWT(jwtClaimsSetKnownIssuer());
        given()
                .header("Authorization", "Bearer " + jwt.serialize())
                .when()
                .get("/protected")
                .then()
                .log().ifValidationFails()
                .statusCode(HttpStatus.OK.value());
    }

    private static JWTClaimsSet jwtClaimsSetKnownIssuer() {
        return jwtClaimsSet(ISS, AUD);
    }

    private static JWTClaimsSet jwtClaimsSet(String issuer, String audience) {
        return buildClaimSet("testsub", issuer, audience, ACR, TimeUnit.MINUTES.toMillis(1));
    }
}
