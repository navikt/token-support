package no.nav.security.token.support.spring

import jakarta.validation.Valid
import no.nav.security.token.support.core.configuration.IssuerProperties
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.validation.annotation.Validated

@ConfigurationProperties("no.nav.security.jwt")
@EnableConfigurationProperties
@Validated
data class MultiIssuerProperties(val issuer: Map<String, @Valid IssuerProperties> = emptyMap())
