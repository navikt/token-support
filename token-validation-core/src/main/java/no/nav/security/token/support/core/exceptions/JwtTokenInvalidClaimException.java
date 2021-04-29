package no.nav.security.token.support.core.exceptions;

import static java.util.stream.Collectors.toMap;

import java.util.Arrays;
import java.util.Map;

import no.nav.security.token.support.core.api.ProtectedWithClaims;
import no.nav.security.token.support.core.api.RequiredIssuers;

public class JwtTokenInvalidClaimException extends RuntimeException {

    public JwtTokenInvalidClaimException(String message) {
        super(message);
    }

    public JwtTokenInvalidClaimException(RequiredIssuers ann) {
        throw new JwtTokenInvalidClaimException("required claims not present in token for any of " + issuersAndClaims(ann));
    }

    public JwtTokenInvalidClaimException(ProtectedWithClaims ann) {
        this("required claims not present in token." + Arrays.asList(ann.claimMap()));
    }

    private static Map<String, String[]> issuersAndClaims(RequiredIssuers ann) {
        return Arrays.stream(ann.value())
                .collect(toMap(ProtectedWithClaims::issuer, ProtectedWithClaims::claimMap));
    }
}
