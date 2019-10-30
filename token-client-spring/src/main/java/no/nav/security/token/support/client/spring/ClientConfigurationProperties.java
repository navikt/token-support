package no.nav.security.token.support.client.spring;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import no.nav.security.token.support.client.core.ClientProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import java.util.Map;


@Getter
@EqualsAndHashCode
@ToString
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
}
