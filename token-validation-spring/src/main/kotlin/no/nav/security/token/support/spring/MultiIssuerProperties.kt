package no.nav.security.token.support.spring

import no.nav.security.token.support.core.configuration.IssuerProperties
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Configuration
import org.springframework.validation.annotation.Validated
import javax.validation.Valid

@Configuration
@ConfigurationProperties(prefix = "no.nav.security.jwt")
@EnableConfigurationProperties
@Validated
data class MultiIssuerProperties(@Valid val issuer: Map<String,IssuerProperties>)