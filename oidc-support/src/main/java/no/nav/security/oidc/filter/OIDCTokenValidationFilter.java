package no.nav.security.oidc.filter;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWTParser;

import no.nav.security.oidc.configuration.MultiIssuerConfiguraton;
import no.nav.security.oidc.context.OIDCClaims;
import no.nav.security.oidc.context.OIDCRequestContextHolder;
import no.nav.security.oidc.context.OIDCValidationContext;
import no.nav.security.oidc.context.TokenContext;
import no.nav.security.oidc.exceptions.OIDCTokenValidatorException;

public class OIDCTokenValidationFilter implements Filter {

	private Logger logger = LoggerFactory.getLogger(OIDCTokenValidationFilter.class);
	private final MultiIssuerConfiguraton config;
	private final OIDCRequestContextHolder contextHolder;
	
	public OIDCTokenValidationFilter(MultiIssuerConfiguraton oidcConfig, OIDCRequestContextHolder contextHolder) {
		this.config = oidcConfig;
		this.contextHolder = contextHolder;
	}

	@Override
	public void destroy() {
		
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		if (request instanceof HttpServletRequest) {
			doTokenValidation((HttpServletRequest) request, (HttpServletResponse) response, chain);
		} else {
			chain.doFilter(request, response);
		}
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {

	}

	private void doTokenValidation(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		List<TokenContext> tokensOnRequest = TokenRetriever.retrieveTokens(config, request);
		List<TokenContext> validatedTokens = new ArrayList<>();
		for(TokenContext token : tokensOnRequest) {
			long start = System.currentTimeMillis();
			try {
				
				config.getIssuer(token.getIssuer()).getTokenValidator().
					assertValidToken(token.getIdToken());
				validatedTokens.add(token);
				logger.debug("token " + token.getIssuer() + " validated OK");
			} catch(OIDCTokenValidatorException ve) {
				logger.warn("invalid token for issuer [" + token.getIssuer() + "].", ve);
			}
			long stop = System.currentTimeMillis();
			logger.debug("validated token [" + token.getIssuer() + "] in " + (stop-start) + "ms");
		}
		OIDCValidationContext validationContext = new OIDCValidationContext();
		for(TokenContext validatedToken : validatedTokens) {
			try {
				validationContext.addValidatedToken(validatedToken.getIssuer(), validatedToken, 
						new OIDCClaims(JWTParser.parse(validatedToken.getIdToken())));
			} catch (ParseException e) {
				logger.warn("failed to parse token despite validated: " + e, e);
			}
		}
		contextHolder.setOIDCValidationContext(validationContext);
		try {
			chain.doFilter(request, response);
		} finally {
			contextHolder.setOIDCValidationContext(null);
		}
	}

}
