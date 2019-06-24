package no.nav.security.token.support.core.validation;

import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration;
import no.nav.security.token.support.core.jwt.JwtToken;
import no.nav.security.token.support.core.http.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class JwtTokenRetriever {

    private static final Logger LOG = LoggerFactory.getLogger(JwtTokenRetriever.class);

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER = "Bearer";

    static List<JwtToken> retrieveUnvalidatedTokens(MultiIssuerConfiguration config, HttpRequest request) {
        return Stream.concat(
            getTokensFromHeader(config, request).stream(),
            getTokensFromCookies(config, request).stream())
            .collect(Collectors.toList());
    }

    private static List<JwtToken> getTokensFromHeader(MultiIssuerConfiguration config, HttpRequest request) {
        try {
            LOG.debug("checking authorization header for tokens");
            String authorization = request.getHeader(AUTHORIZATION_HEADER);
            if (authorization != null) {
                String[] headerValues = authorization.split(",");
                return extractBearerTokens(headerValues)
                    .stream()
                    .map(JwtToken::new)
                    .filter(jwtToken -> config.getIssuer(jwtToken.getIssuer()).isPresent())
                    .collect(Collectors.toList());
            }
            LOG.debug("no tokens found in authorization header");
        } catch (Exception e) {
            LOG.warn("received exception when attempting to extract and parse token from Authorization header", e);
        }
        return Collections.emptyList();
    }

    private static List<JwtToken> getTokensFromCookies(MultiIssuerConfiguration config, HttpRequest request) {
        try {
            List<HttpRequest.NameValue> cookies = request.getCookies() != null ? Arrays.asList(request.getCookies()) : Collections.emptyList();
            return cookies.stream()
                .filter(nameValue -> containsCookieName(config, nameValue.getName()))
                .map(nameValue -> new JwtToken(nameValue.getValue()))
                .collect(Collectors.toList());
        } catch (Exception e) {
            LOG.warn("received exception when attempting to extract and parse token from cookie", e);
            return Collections.emptyList();
        }
    }

    private static boolean containsCookieName(MultiIssuerConfiguration configuration, String cookieName) {
        return configuration.getIssuers().values().stream()
            .anyMatch(issuerConfiguration -> issuerConfiguration.getCookieName().equals(cookieName));
    }

    private static List<String> extractBearerTokens(String... headerValues) {
        return Arrays.stream(headerValues)
            .map(s -> s.split(" "))
            .filter(pair -> pair.length == 2)
            .filter(pair -> pair[0].trim().equalsIgnoreCase(BEARER))
            .map(pair -> pair[1].trim())
            .collect(Collectors.toList());
    }
}
