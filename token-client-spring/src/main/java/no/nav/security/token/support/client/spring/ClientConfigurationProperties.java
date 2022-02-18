package no.nav.security.token.support.client.spring;

import no.nav.security.token.support.client.core.ClientProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import java.util.Map;
import java.util.Objects;


@Validated
@ConfigurationProperties("no.nav.security.jwt.client")
public class ClientConfigurationProperties {

    @NotEmpty
    @Valid
    private final Map<String, ClientProperties> registration;

    @ConstructorBinding
    public ClientConfigurationProperties(@NotEmpty @Valid Map<String, ClientProperties> registration) {
        this.registration = registration;
    }

    public @NotEmpty @Valid Map<String, ClientProperties> getRegistration() {
        return this.registration;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ClientConfigurationProperties that = (ClientConfigurationProperties) o;
        return Objects.equals(registration, that.registration);
    }

    @Override
    public int hashCode() {
        return Objects.hash(registration);
    }

    @Override
    public String toString() {
        return "ClientConfigurationProperties(registration=" + this.getRegistration() + ")";
    }
}
