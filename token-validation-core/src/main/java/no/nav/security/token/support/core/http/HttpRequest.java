package no.nav.security.token.support.core.http;

/***
 * Abstraction interface for an HTTP request to avoid dependencies on specific implementations such as HttpServletRequest etc.
 */
public interface HttpRequest {
    String getHeader(String headerName);
    NameValue[] getCookies();

    interface NameValue {
        String getName();
        String getValue();
    }
}
