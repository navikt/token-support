package no.nav.security.token.support.core.exceptions;

import static java.util.stream.Collectors.toList;

import java.util.Arrays;
import java.util.List;

import no.nav.security.token.support.core.api.ProtectedWithClaims;
import no.nav.security.token.support.core.api.RequiredIssuers;

public class JwtTokenMissingException extends RuntimeException {
    public JwtTokenMissingException(String message) {
        super(message);
    }

    public JwtTokenMissingException(RequiredIssuers ann) {
        this("no valid token found in validation context for any of the issuers " + issuers(ann));
    }

    public JwtTokenMissingException() {
        this("no valid token found in validation context");
    }

    private static List<String> issuers(RequiredIssuers ann) {
        return Arrays.stream(ann.value())
                .map(ProtectedWithClaims::issuer)
                .collect(toList());
    }
}
