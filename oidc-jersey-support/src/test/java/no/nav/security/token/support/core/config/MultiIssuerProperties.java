package no.nav.security.token.support.core.config;

import no.nav.security.token.support.core.configuration.IssuerProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import java.util.HashMap;
import java.util.Map;

@Configuration
@ConfigurationProperties(prefix = "no.nav.security.oidc")
@EnableConfigurationProperties
@Validated
public class MultiIssuerProperties {
	
	@Valid
	private final Map<String, IssuerProperties> issuer = new HashMap<>();
	
	public Map<String, IssuerProperties> getIssuer(){
		return issuer;
	}

	@Override
	public String toString() {
		return "MultiIssuerConfigurationProperties [issuer=" + issuer + "]";
	}
}
