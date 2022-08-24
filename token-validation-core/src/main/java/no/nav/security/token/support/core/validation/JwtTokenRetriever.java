package no.nav.security.token.support.core.validation;

import no.nav.security.token.support.core.configuration.IssuerConfiguration;
import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration;
import no.nav.security.token.support.core.http.HttpRequest;
import no.nav.security.token.support.core.jwt.JwtToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
public class JwtTokenRetriever {

    private static final Logger LOG = LoggerFactory.getLogger(JwtTokenRetriever.class);
    private static final String BEARER = "Bearer";

    static List<JwtToken> retrieveUnvalidatedTokens(MultiIssuerConfiguration config, HttpRequest request) {
        return Stream.concat(
            getTokensFromHeader(config, request).stream(),
            getTokensFromCookies(config, request).stream())
            .toList();
    }

    private static List<JwtToken> getTokensFromHeader(MultiIssuerConfiguration config, HttpRequest request) {
        try {
            LOG.debug("Checking authorization header for tokens");

            var issuers = config.getIssuers();
            Optional<IssuerConfiguration> issuer = issuers.values().stream().filter(it -> request.getHeader(it.getHeaderName()) != null).findFirst();

            if (issuer.isPresent()) {
                var authorization = request.getHeader(issuer.get().getHeaderName());
                String[] headerValues = authorization.split(",");
                return extractBearerTokens(headerValues)
                    .stream()
                    .map(JwtToken::new)
                    .filter(jwtToken -> config.getIssuer(jwtToken.getIssuer()).isPresent())
                    .toList();
            }
            LOG.debug("No tokens found in authorization header");
        } catch (Exception e) {
            LOG.warn("Received exception when attempting to extract and parse token from Authorization header", e);
        }
        return List.of();
    }

    private static List<JwtToken> getTokensFromCookies(MultiIssuerConfiguration config, HttpRequest request) {
        try {
            List<HttpRequest.NameValue> cookies = request.getCookies() != null ? Arrays.asList(request.getCookies()) : List.of();
            return cookies.stream()
                .filter(nameValue -> containsCookieName(config, nameValue.getName()))
                .map(nameValue -> new JwtToken(nameValue.getValue()))
                .toList();
        } catch (Exception e) {
            LOG.warn("received exception when attempting to extract and parse token from cookie", e);
            return List.of();
        }
    }

    private static boolean containsCookieName(MultiIssuerConfiguration configuration, String cookieName) {
        return configuration.getIssuers().values().stream()
            .anyMatch(issuerConfiguration -> cookieName.equalsIgnoreCase(issuerConfiguration.getCookieName()));
    }

    private static List<String> extractBearerTokens(String... headerValues) {
        return Arrays.stream(headerValues)
            .map(s -> s.split(" "))
            .filter(pair -> pair.length == 2)
            .filter(pair -> pair[0].trim().equalsIgnoreCase(BEARER))
            .map(pair -> pair[1].trim())
            .toList();
    }
}
