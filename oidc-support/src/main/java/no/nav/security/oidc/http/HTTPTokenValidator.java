package no.nav.security.oidc.http;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWTParser;

import no.nav.security.oidc.configuration.MultiIssuerConfiguration;
import no.nav.security.oidc.context.OIDCClaims;
import no.nav.security.oidc.context.OIDCValidationContext;
import no.nav.security.oidc.context.TokenContext;
import no.nav.security.oidc.exceptions.OIDCTokenValidatorException;

public class HTTPTokenValidator {

    private static final Logger LOG = LoggerFactory.getLogger(HTTPTokenValidator.class);

    public static OIDCValidationContext validateTokensAndCreateContext(MultiIssuerConfiguration config, TokenRetriever.HttpRequest request) {
        List<TokenContext> tokensOnRequest = TokenRetriever.retrieveTokens(config, request);
        List<TokenContext> validatedTokens = new ArrayList<>();
        for (TokenContext token : tokensOnRequest) {
            long start = System.currentTimeMillis();
            try {
                config.getIssuer(token.getIssuer()).getTokenValidator().assertValidToken(token.getIdToken());
                validatedTokens.add(token);
                LOG.debug("Token {} validated OK", token.getIssuer());
            } catch (OIDCTokenValidatorException ve) {
                LOG.info("Invalid token for issuer [{}, expires at {}]", token.getIssuer(), ve.getExpiryDate(), ve);
            }
            long stop = System.currentTimeMillis();
            LOG.debug("Validated token [{}] in {}ms", token.getIssuer(), (stop - start));
        }
        OIDCValidationContext validationContext = new OIDCValidationContext();
        for (TokenContext validatedToken : validatedTokens) {
            try {
                validationContext.addValidatedToken(validatedToken.getIssuer(), validatedToken,
                        new OIDCClaims(JWTParser.parse(validatedToken.getIdToken())));
            } catch (ParseException e) {
                LOG.warn("Failed to parse token despite validated", e);
            }
        }
        return validationContext;
    }

}
