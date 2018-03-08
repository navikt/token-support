package no.nav.security.oidc.filter;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import no.nav.security.oidc.OIDCConstants;
import no.nav.security.oidc.configuration.OIDCValidationConfiguraton;
import no.nav.security.oidc.context.TokenContext;

public class TokenRetriever {

	private static Logger logger = LoggerFactory.getLogger(TokenRetriever.class);

	public static List<TokenContext> retrieveTokens(OIDCValidationConfiguraton config, HttpServletRequest request) {
		List<TokenContext> tokens = new ArrayList<>();

		// find tokens store in Authorization header
		logger.debug("checking authorization header ...");
		String auth = request.getHeader(OIDCConstants.AUTHORIZATION_HEADER);
		if(auth != null) {
			String[] authElements = auth.split(",");
			for (String authElement : authElements) {
				try {
					String[] pair = authElement.split(" ");
					if (pair[0].trim().equalsIgnoreCase("bearer")) {
						String token = pair[1].trim();
						JWT jwt = JWTParser.parse(token);
						if (config.getIssuer(jwt.getJWTClaimsSet().getIssuer()) != null) {
							String issuer = config.getIssuer(jwt.getJWTClaimsSet().getIssuer()).getName();
							tokens.add(new TokenContext(issuer, token));
						}
					}
				} catch (Exception e) {
					// log, ignore and jump to next
					logger.warn("Failed to parse Authorization header: " + e.toString(), e);
				}
			}
		}

		// find tokens stored in cookies
		logger.debug("checking for tokens in cookies ...");
		Cookie[] cookies = request.getCookies();
		if(cookies != null) {
			for (String issuer : config.getIssuerNames()) {
				String expectedName = config.getIssuer(issuer).getCookieName();
				expectedName = expectedName == null ? OIDCConstants.getDefaultCookieName(issuer) : expectedName;
				for (Cookie cookie : cookies) {
					if (cookie.getName().equalsIgnoreCase(expectedName)) {
						tokens.add(new TokenContext(issuer, cookie.getValue()));
					}
				}
			}
		}

		return tokens;
	}

}
