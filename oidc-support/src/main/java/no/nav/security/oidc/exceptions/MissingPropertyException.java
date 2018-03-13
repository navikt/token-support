package no.nav.security.oidc.exceptions;

@SuppressWarnings("serial")
public class MissingPropertyException extends IllegalStateException {

	public MissingPropertyException(String message) {
		super(message);
	}
	public MissingPropertyException(Throwable throwable) {
		super(throwable);
	}
}
