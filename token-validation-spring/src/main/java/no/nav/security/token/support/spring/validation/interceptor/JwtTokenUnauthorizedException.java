package no.nav.security.token.support.spring.validation.interceptor;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@SuppressWarnings("serial")
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class JwtTokenUnauthorizedException extends RuntimeException {
	
	public JwtTokenUnauthorizedException(String msg) {
		super(msg);
	}

    public JwtTokenUnauthorizedException(Throwable cause) {
        super(cause);
    }
}
