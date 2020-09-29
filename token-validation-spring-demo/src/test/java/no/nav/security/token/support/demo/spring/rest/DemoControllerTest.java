package no.nav.security.token.support.demo.spring.rest;

import io.restassured.module.mockmvc.RestAssuredMockMvc;
import no.nav.security.mock.oauth2.MockOAuth2Server;
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback;
import no.nav.security.token.support.demo.spring.DemoApplication;
import no.nav.security.token.support.spring.test.EnableMockOAuth2Server;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.setup.ConfigurableMockMvcBuilder;
import org.springframework.test.web.servlet.setup.MockMvcConfigurer;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.Filter;
import java.util.Collection;
import java.util.Collections;

import static io.restassured.module.mockmvc.RestAssuredMockMvc.given;

@SpringBootTest(classes = DemoApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@EnableMockOAuth2Server
class DemoControllerTest {
    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private MockOAuth2Server server;

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
    void noTokenInRequest() {
        given()
            .when()
            .get("/demo/protected")
            .then()
            .log().ifValidationFails()
            .statusCode(HttpStatus.UNAUTHORIZED.value());

    }

    @Test
    void validTokenInRequestMultipleIssuers() {
        String token1 = token("issuer1", "subject1", "demoapplication");
        String token2 = token("issuer2", "subject1", "demoapplication");
        String uri = "/demo/protected";

        given()
            .header("Authorization", "Bearer " + token1)
            .when()
            .get(uri)
            .then()
            .log().ifValidationFails()
            .statusCode(HttpStatus.OK.value());

        given()
            .header("Authorization", "Bearer " + token2)
            .when()
            .get(uri)
            .then()
            .log().ifValidationFails()
            .statusCode(HttpStatus.OK.value());
    }

    private String token(String issuerId, String subject, String audience){
        return server.issueToken(
            issuerId,
            "theclientid",
            new DefaultOAuth2TokenCallback(
                issuerId,
                subject,
                audience,
                Collections.emptyMap(),
                3600
            )
        ).serialize();
    }
}
