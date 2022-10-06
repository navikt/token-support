package no.nav.security.token.support.core.config;

import jakarta.validation.Valid;
import no.nav.security.token.support.core.configuration.IssuerProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.HashMap;
import java.util.Map;

@ConfigurationProperties("no.nav.security.jwt")
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
