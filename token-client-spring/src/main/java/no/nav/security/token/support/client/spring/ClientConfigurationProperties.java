package no.nav.security.token.support.client.spring;

import lombok.Data;
import no.nav.security.token.support.client.core.ClientProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import java.util.LinkedHashMap;
import java.util.Map;


@Data
@Validated
@Configuration
@EnableConfigurationProperties
@ConfigurationProperties(ClientConfigurationProperties.PREFIX)
public class ClientConfigurationProperties {

    public static final String PREFIX = "no.nav.security.jwt.client";

    @NotEmpty
    @Valid
    private Map<String, ClientProperties> registration = new LinkedHashMap<>();
}
