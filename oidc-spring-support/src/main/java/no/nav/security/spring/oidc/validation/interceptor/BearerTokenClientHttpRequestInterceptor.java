package no.nav.security.spring.oidc.validation.interceptor;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import no.nav.security.oidc.OIDCConstants;
import no.nav.security.oidc.context.OIDCRequestContextHolder;
import no.nav.security.oidc.context.OIDCValidationContext;

public class BearerTokenClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {

	private OIDCRequestContextHolder contextHolder;
	
	public BearerTokenClientHttpRequestInterceptor(OIDCRequestContextHolder contextHolder) {
		this.contextHolder = contextHolder;
	}
	
	private Logger logger = LoggerFactory.getLogger(BearerTokenClientHttpRequestInterceptor.class);

	@Override
	public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
			throws IOException {

		OIDCValidationContext context = (OIDCValidationContext) contextHolder
				.getOIDCValidationContext();
		
		if(context != null && context.hasValidToken()) {
			logger.debug("adding tokens to Authorization header");
			StringBuffer headerValue = new StringBuffer();
			boolean first = true;
			for(String issuer : context.getIssuers()) {
				logger.debug("adding token for issuer {}", issuer);
				if(!first) {
					headerValue.append(",");
				}
				headerValue.append("Bearer " + context.getToken(issuer).getIdToken());				
			}			
			request.getHeaders().add(OIDCConstants.AUTHORIZATION_HEADER, headerValue.toString());
		} else {
			logger.debug("no tokens found, nothing added to request");
		}
		return execution.execute(request, body);
	}

}
