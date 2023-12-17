package no.nav.security.token.support.spring

import jakarta.validation.Valid
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.validation.annotation.Validated
import no.nav.security.token.support.core.configuration.IssuerProperties

@ConfigurationProperties("no.nav.security.jwt")
@EnableConfigurationProperties
@Validated
data class MultiIssuerProperties(@Valid val issuer: Map<String,IssuerProperties> = emptyMap())