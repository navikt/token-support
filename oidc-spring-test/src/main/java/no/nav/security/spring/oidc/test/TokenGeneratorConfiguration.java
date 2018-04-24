package no.nav.security.spring.oidc.test;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;

import no.nav.security.oidc.configuration.OIDCResourceRetriever;

@Configuration
@Import(TokenGeneratorController.class)
public class TokenGeneratorConfiguration {
	
	/**
	 * To be able to ovverride the oidc validation properties in
	 * EnableOIDCTokenValidationConfiguration in oidc-spring-support
	 */
	@Bean
    @Primary
    OIDCResourceRetriever overrideOidcResourceRetriever(){
    	return new FileResourceRetriever("/metadata.json", "/jwkset.json");
    }	
}
