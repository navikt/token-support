package no.nav.security.oidc.filter;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import no.nav.security.oidc.http.HttpHeaders;

public class PropagatedHeaders {
	
	private static Logger logger = LoggerFactory.getLogger(PropagatedHeaders.class);
	
	public static String[] defaultHeaders = {"x-request-id", "x-b3-traceid", "x-b3-spanid", "x-b3-parentspanid", "x-b3-sampled", "x-b3-flags", "x-ot-span-context"};
	
	public static HttpHeaders getDefaults(HttpServletRequest req) {
		HttpHeaders headers = new HttpHeaders();
		for(String header : defaultHeaders) {
			String value = req.getHeader(header);
			if(value != null) {
				logger.debug("reading header [" + header + "]");
				headers.addHeader(header, value);
			} else {
				logger.debug("header [" + header + "] had no value, ignoring");
			}
		}
		return headers;
	}

}
