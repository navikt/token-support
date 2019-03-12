package no.nav.security.oidc.http;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import no.nav.security.oidc.OIDCConstants;
import no.nav.security.oidc.configuration.MultiIssuerConfiguration;
import no.nav.security.oidc.context.TokenContext;

public class TokenRetriever {

    public interface NameValue {
        String getName();
        String getValue();
    }

    public interface HttpRequest {
        String getHeader(String headerName);
        NameValue[] getCookies();
    }

    private static final Logger LOG = LoggerFactory.getLogger(TokenRetriever.class);

    static List<TokenContext> retrieveTokens(MultiIssuerConfiguration config, HttpRequest request) {
        List<TokenContext> tokens = new ArrayList<>();

        LOG.debug("Checking authorization header");
        String auth = request.getHeader(OIDCConstants.AUTHORIZATION_HEADER);
        if (auth != null) {
            String[] authElements = auth.split(",");
            for (String authElement : authElements) {
                try {
                    String[] pair = authElement.split(" ");
                    if (pair[0].trim().equalsIgnoreCase("bearer")) {
                        String token = pair[1].trim();
                        Optional<TokenContext> tokenContext = createTokenContext(config, token);
                        if (tokenContext.isPresent()) {
                            tokens.add(tokenContext.get());
                            LOG.debug("Found token for issuer {}. adding new unvalidated tokencontext.",
                                    tokenContext.get().getIssuer());
                        }
                    }
                } catch (Exception e) {
                    // log, ignore and jump to next
                    LOG.warn("Failed to parse Authorization header: " + e.toString(), e);
                }
            }
        }

        LOG.debug("Checking for tokens in cookies");
        NameValue[] cookies = request.getCookies();
        if (cookies != null) {
            for (String issuer : config.getIssuerShortNames()) {
                String expectedName = config.getIssuer(issuer).getCookieName();
                expectedName = expectedName == null ? OIDCConstants.getDefaultCookieName(issuer) : expectedName;
                for (NameValue cookie : cookies) {
                    if (cookie.getName().equalsIgnoreCase(expectedName)) {
                        LOG.debug("Found cookie with expected name {}", expectedName);
                        Optional<TokenContext> tokenContext = createTokenContext(config, cookie.getValue());
                        if (tokenContext.isPresent()) {
                            tokens.add(tokenContext.get());
                            LOG.debug("Found token for issuer {}. adding new unvalidated tokencontext.",
                                    tokenContext.get().getIssuer());
                        }
                        return tokens;
                    }
                }
            }
        }

        return tokens;
    }

    private static Optional<TokenContext> createTokenContext(MultiIssuerConfiguration config, String token) {
        try {
            JWT jwt = JWTParser.parse(token);
            if (config.getIssuer(jwt.getJWTClaimsSet().getIssuer()) != null) {
                String issuer = config.getIssuer(jwt.getJWTClaimsSet().getIssuer()).getName();
                return Optional.of(new TokenContext(issuer, token));
            }
            return Optional.empty();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }
}
