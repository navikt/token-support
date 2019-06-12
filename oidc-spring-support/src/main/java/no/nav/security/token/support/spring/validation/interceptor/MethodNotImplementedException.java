package no.nav.security.token.support.spring.validation.interceptor;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@SuppressWarnings("serial")
@ResponseStatus(HttpStatus.NOT_IMPLEMENTED)
public class MethodNotImplementedException extends RuntimeException {
	
	public MethodNotImplementedException(String msg) {
		super(msg);
	}

}
