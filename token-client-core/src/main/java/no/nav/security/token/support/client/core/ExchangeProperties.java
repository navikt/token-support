package no.nav.security.token.support.client.core;

import lombok.*;

import javax.validation.constraints.NotNull;
import java.util.Objects;

@EqualsAndHashCode
@ToString
@Getter
@Setter
public class ExchangeProperties {

    @NotNull
    private final String audience;
    private final String resource;

    @Builder(toBuilder = true)
    public ExchangeProperties(@NotNull String audience, String resource) {
        this.audience = audience;
        this.resource = resource;
        validateAfterPropertiesSet();
    }

    private void validateAfterPropertiesSet() {
        Objects.requireNonNull(audience, "audience must be set");
    }

    public String subjectTokenType() {
        return "urn:ietf:params:oauth:token-type:jwt";
    }
}
