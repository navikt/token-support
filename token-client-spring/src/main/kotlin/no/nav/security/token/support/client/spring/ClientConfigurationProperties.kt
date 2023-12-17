package no.nav.security.token.support.client.spring

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.validation.annotation.Validated
import no.nav.security.token.support.client.core.ClientProperties

@Validated
@ConfigurationProperties("no.nav.security.jwt.client")
data class ClientConfigurationProperties(val registration: @NotEmpty @Valid Map<String, ClientProperties>)