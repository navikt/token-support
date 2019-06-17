package no.nav.security.token.support.spring.validation.interceptor;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import java.io.IOException;

import no.nav.security.token.support.core.context.TokenValidationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import no.nav.security.token.support.core.JwtTokenConstants;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;

public class BearerTokenClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {

	private final TokenValidationContextHolder contextHolder;
	
	public BearerTokenClientHttpRequestInterceptor(TokenValidationContextHolder contextHolder) {
		this.contextHolder = contextHolder;
	}
	
	private final Logger logger = LoggerFactory.getLogger(BearerTokenClientHttpRequestInterceptor.class);

	@Override
	public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
			throws IOException {

		TokenValidationContext context = contextHolder.getTokenValidationContext();
		
		if(context != null && context.hasValidToken()) {
			logger.debug("adding tokens to Authorization header");
			StringBuilder headerValue = new StringBuilder();
			boolean first = true;
			for(String issuer : context.getIssuers()) {
				logger.debug("adding token for issuer {}", issuer);
				if(!first) {
					headerValue.append(",");
				}
				headerValue.append("Bearer " + context.getJwtToken(issuer).getTokenAsString());
				first = false;
			}			
			request.getHeaders().add(JwtTokenConstants.AUTHORIZATION_HEADER, headerValue.toString());
		} else {
			logger.debug("no tokens found, nothing added to request");
		}
		return execution.execute(request, body);
	}

}
