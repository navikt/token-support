package no.nav.security.token.support.jaxrs

import org.glassfish.jersey.server.ResourceConfig
import org.glassfish.jersey.servlet.ServletContainer
import org.glassfish.jersey.servlet.ServletProperties.JAXRS_APPLICATION_CLASS
import org.springframework.boot.SpringBootConfiguration
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.web.embedded.jetty.JettyServletWebServerFactory
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.boot.web.servlet.ServletRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.web.context.request.RequestContextListener
import no.nav.security.token.support.core.configuration.IssuerProperties
import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever
import no.nav.security.token.support.jaxrs.rest.ProtectedClassResource
import no.nav.security.token.support.jaxrs.rest.ProtectedMethodResource
import no.nav.security.token.support.jaxrs.rest.ProtectedWithClaimsClassResource
import no.nav.security.token.support.jaxrs.rest.TokenResource
import no.nav.security.token.support.jaxrs.rest.UnprotectedClassResource
import no.nav.security.token.support.jaxrs.rest.WithoutAnnotationsResource
import no.nav.security.token.support.jaxrs.servlet.JaxrsJwtTokenValidationFilter
import no.nav.security.token.support.spring.MultiIssuerProperties

@SpringBootConfiguration
@EnableConfigurationProperties(MultiIssuerProperties::class)
class Config {

    @Bean
    fun servletWebServerFactory()  = JettyServletWebServerFactory(0)

    @Bean
    fun jerseyServletRegistration() =
        ServletRegistrationBean(ServletContainer()).apply<ServletRegistrationBean<ServletContainer>> {
            addInitParameter(JAXRS_APPLICATION_CLASS, RestConfiguration::class.java.name)
        }

    @Bean
    fun oidcTokenValidationFilterBean(config : MultiIssuerConfiguration) = FilterRegistrationBean(JaxrsJwtTokenValidationFilter(config))

    @ConfigurationProperties("no.nav.security.jwt")
    class MultiIssuerProperties(val issuer : Map<String, IssuerProperties>)

    @Bean
    fun multiIssuerProperties(properties : Map<String, IssuerProperties>) = MultiIssuerProperties(properties)

    @Bean
    fun multiIssuerConfiguration(issuerProperties : MultiIssuerProperties) =
         MultiIssuerConfiguration(issuerProperties.issuer, FileResourceRetriever("/metadata.json", "/jwkset.json"))

    @Bean
    fun requestContextListener() = RequestContextListener()

    @Bean
    fun oidcResourceRetriever() = ProxyAwareResourceRetriever()

    class RestConfiguration : ResourceConfig() {
        init {
            register(JwtTokenContainerRequestFilter::class.java)
            register(TokenResource::class.java)
            register(ProtectedClassResource::class.java)
            register(ProtectedMethodResource::class.java)
            register(ProtectedWithClaimsClassResource::class.java)
            register(UnprotectedClassResource::class.java)
            register(WithoutAnnotationsResource::class.java)
            register(TestTokenGeneratorResource::class.java)
        }
    }
}