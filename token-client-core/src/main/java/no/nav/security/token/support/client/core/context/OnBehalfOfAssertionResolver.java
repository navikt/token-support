package no.nav.security.token.support.client.core.context;

import java.util.Optional;

public interface OnBehalfOfAssertionResolver {
    Optional<String> assertion();
}
