package no.nav.security.token.support.spring

import no.nav.security.token.support.core.JwtTokenConstants.BEARER_TOKEN_DONT_PROPAGATE_ENV_PROPERTY
import no.nav.security.token.support.core.JwtTokenConstants.EXPIRY_THRESHOLD_ENV_PROPERTY
import no.nav.security.token.support.core.JwtTokenConstants.TOKEN_VALIDATION_FILTER_ORDER_PROPERTY
import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import no.nav.security.token.support.core.validation.JwtTokenValidationHandler
import no.nav.security.token.support.filter.JwtTokenExpiryFilter
import no.nav.security.token.support.filter.JwtTokenValidationFilter
import no.nav.security.token.support.spring.api.EnableJwtTokenValidation
import no.nav.security.token.support.spring.validation.interceptor.BearerTokenClientHttpRequestInterceptor
import no.nav.security.token.support.spring.validation.interceptor.JwtTokenHandlerInterceptor
import no.nav.security.token.support.spring.validation.interceptor.SpringJwtTokenAnnotationHandler
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.ImportAware
import org.springframework.core.Ordered.HIGHEST_PRECEDENCE
import org.springframework.core.annotation.AnnotationAttributes
import org.springframework.core.annotation.AnnotationAttributes.fromMap
import org.springframework.core.env.Environment
import org.springframework.core.type.AnnotationMetadata
import org.springframework.web.context.request.RequestContextListener
import org.springframework.web.servlet.config.annotation.InterceptorRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import java.net.URL
import java.util.EnumSet
import javax.servlet.DispatcherType.ASYNC
import javax.servlet.DispatcherType.FORWARD
import javax.servlet.DispatcherType.REQUEST
import javax.servlet.Filter


@Configuration
@EnableConfigurationProperties(MultiIssuerProperties::class)
class EnableJwtTokenValidationConfiguration(private val env: Environment) : WebMvcConfigurer, ImportAware {
    private val log = LoggerFactory.getLogger(EnableJwtTokenValidationConfiguration::class.java)
    private lateinit var attrs: AnnotationAttributes

    override fun addInterceptors(registry: InterceptorRegistry) {
        registry.addInterceptor(controllerInterceptor())
    }

    override fun setImportMetadata(meta: AnnotationMetadata) {
        attrs = fromMap(meta.getAnnotationAttributes(EnableJwtTokenValidation::class.java.name, false)) ?: throw IllegalArgumentException("@EnableJwtTokenValidation is not present on importing class $meta.className")
    }

    //TO-DO remove support for global proxy - should be set per issuer config
    @Bean
    fun oidcResourceRetriever() = ProxyAwareResourceRetriever(configuredProxy(), env.getProperty("https.plaintext", Boolean::class.java, false))

    @Bean
    fun multiIssuerConfiguration(issuerProperties: MultiIssuerProperties, resourceRetriever: ProxyAwareResourceRetriever?) = MultiIssuerConfiguration(issuerProperties.issuer, resourceRetriever)

    @Bean
    fun oidcRequestContextHolder() = SpringTokenValidationContextHolder()

    @Bean
    fun requestContextListener() = RequestContextListener()

    @Bean
    fun tokenValidationFilter(config: MultiIssuerConfiguration?, h: TokenValidationContextHolder?) = JwtTokenValidationFilter(JwtTokenValidationHandler(config), h)

    @Bean
    @ConditionalOnProperty(EXPIRY_THRESHOLD_ENV_PROPERTY)
    fun expiryFilter(h: TokenValidationContextHolder,@Value("\${$EXPIRY_THRESHOLD_ENV_PROPERTY}") threshold: Long) = JwtTokenExpiryFilter(h,threshold)

    @Bean
    @ConditionalOnProperty(BEARER_TOKEN_DONT_PROPAGATE_ENV_PROPERTY, matchIfMissing = true)
    fun bearerTokenClientHttpRequestInterceptor(tokenValidationContextHolder: TokenValidationContextHolder) =  BearerTokenClientHttpRequestInterceptor(tokenValidationContextHolder)

    @Bean
    fun oidcTokenValidationFilterRegistrationBean(filter: JwtTokenValidationFilter, @Value("\${$TOKEN_VALIDATION_FILTER_ORDER_PROPERTY:$HIGHEST_PRECEDENCE}") order : Int) = filterRegistrationBeanFor(filter, order)

    @Bean
    @ConditionalOnProperty(EXPIRY_THRESHOLD_ENV_PROPERTY)
    fun oidcTokenExpiryFilterRegistrationBean(filter: JwtTokenExpiryFilter) = filterRegistrationBeanFor(filter,2)

    private fun filterRegistrationBeanFor(filter: Filter, order: Int) =
        FilterRegistrationBean(filter)
            .also { log.info("Registering ${filter.javaClass.simpleName}") }
            .apply {
                setOrder(order)
                setDispatcherTypes(EnumSet.of(REQUEST, FORWARD, ASYNC))
            }

    private fun controllerInterceptor()  = JwtTokenHandlerInterceptor(attrs,SpringJwtTokenAnnotationHandler(SpringTokenValidationContextHolder()))

    private fun configuredProxy() = env.getProperty(env.getProperty("http.proxy.parametername", "http.proxy"),URL::class.java)?.apply {
            if (env.getProperty("nais.cluster.name","local").contains("gcp")) {
                log.warn("You have enabled proxying in GCP, this is probably not what you want")
            }
        }
}