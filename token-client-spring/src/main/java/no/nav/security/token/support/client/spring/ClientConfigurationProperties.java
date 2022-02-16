package no.nav.security.token.support.client.spring;

import no.nav.security.token.support.client.core.ClientProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import java.util.Map;


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

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof ClientConfigurationProperties)) return false;
        final ClientConfigurationProperties other = (ClientConfigurationProperties) o;
        if (!other.canEqual((Object) this)) return false;
        final Object this$registration = this.getRegistration();
        final Object other$registration = other.getRegistration();
        if (this$registration == null ? other$registration != null : !this$registration.equals(other$registration))
            return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof ClientConfigurationProperties;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $registration = this.getRegistration();
        result = result * PRIME + ($registration == null ? 43 : $registration.hashCode());
        return result;
    }

    public String toString() {
        return "ClientConfigurationProperties(registration=" + this.getRegistration() + ")";
    }
}
