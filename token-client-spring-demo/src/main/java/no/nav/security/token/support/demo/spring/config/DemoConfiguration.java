package no.nav.security.token.support.demo.spring.config;

import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse;
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService;
import no.nav.security.token.support.client.spring.ClientConfigurationProperties;
import no.nav.security.token.support.client.spring.oauth2.EnableOAuth2Client;
import no.nav.security.token.support.spring.api.EnableJwtTokenValidation;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.web.client.RestTemplate;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Optional;

/***
 *  JUST AN EXAMPLE ON HOW RESTTEMPLATES CAN BE CONFIGURED
 *  TO DYNAMICALLY REQUEST ACCESS TOKENS BASED ON YAML CONFIG
 *
 *  THE ANNOTATIONS @DemoClient1 AND @DemoClient2 ARE MADE SOLELY FOR THIS DEMO,
 *  JUST TO BE MORE EXPLICIT ON QUALIFING BEANS AND AUTOWIRING CANDIDATES, AND SHOW THAT
 *  YOU WILL PROBABLY NEED ONE RESTTEMPLATE PER OAUTH 2.0 CLIENT CONFIGURATION.
 *
 *  THE ONLY REQUIRED ELEMENTS IN THIS CONFIGURATION ARE:
 *  * THE @EnableOAuth2Client ANNOTATION
 *  * THE ClientConfigurationProperties AND OAuth2AccessTokenService WHICH CAN BE UTILIZED TO GET TOKENS
 */
@EnableOAuth2Client(cacheEnabled = true)
@EnableJwtTokenValidation
@Configuration
public class DemoConfiguration {

    @Bean
    @DemoClient1
    RestTemplate demoClient1RestTemplate(RestTemplateBuilder restTemplateBuilder,
                                         ClientConfigurationProperties clientConfigurationProperties,
                                         OAuth2AccessTokenService oAuth2AccessTokenService) {

        ClientProperties clientProperties =
            Optional.ofNullable(clientConfigurationProperties.getRegistration().get("democlient1"))
                .orElseThrow(() -> new RuntimeException("could not find oauth2 client config for democlient1"));

        return restTemplateBuilder
            .additionalInterceptors(bearerTokenInterceptor(clientProperties, oAuth2AccessTokenService))
            .build();
    }

    @Bean
    @DemoClient2
    RestTemplate demoClient2RestTemplate(RestTemplateBuilder restTemplateBuilder,
                                         ClientConfigurationProperties clientConfigurationProperties,
                                         OAuth2AccessTokenService oAuth2AccessTokenService) {

        ClientProperties clientProperties =
            Optional.ofNullable(clientConfigurationProperties.getRegistration().get("democlient2"))
                .orElseThrow(() -> new RuntimeException("could not find oauth2 client config for democlient2"));

        return restTemplateBuilder
            .additionalInterceptors(bearerTokenInterceptor(clientProperties, oAuth2AccessTokenService))
            .build();
    }


    private ClientHttpRequestInterceptor bearerTokenInterceptor(ClientProperties clientProperties,
                                                                OAuth2AccessTokenService oAuth2AccessTokenService) {
        return (request, body, execution) -> {
            OAuth2AccessTokenResponse response =
                oAuth2AccessTokenService.getAccessToken(clientProperties);
            request.getHeaders().setBearerAuth(response.getAccessToken());
            return execution.execute(request, body);
        };
    }

    @Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER, ElementType.TYPE,
        ElementType.ANNOTATION_TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @Qualifier
    public @interface DemoClient1 {

    }

    @Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER, ElementType.TYPE,
        ElementType.ANNOTATION_TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @Qualifier
    public @interface DemoClient2 {

    }
}
