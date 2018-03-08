package no.nav.security.spring.oidc.validation.interceptor;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@SuppressWarnings("serial")
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class OIDCUnauthorizedException extends RuntimeException {
	
	public OIDCUnauthorizedException(String msg) {
		super(msg);
	}

}
