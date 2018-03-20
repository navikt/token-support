package no.nav.security.spring.oidc.test;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;

import no.nav.security.oidc.http.HttpClient;

@Configuration
@Import(TokenGeneratorController.class)
public class TokenGeneratorConfiguration {
	
	@Bean
    @Primary
    /**
     * To be able to ovverride the oidc validation properties in OIDCTokenValidationConfiguration in oidc-spring-support
     */
    HttpClient overrideSpringHttpClient(){
    	return new JsonFileHttpClient("/metadata.json", "/jwkset.json");
    }
	
}
