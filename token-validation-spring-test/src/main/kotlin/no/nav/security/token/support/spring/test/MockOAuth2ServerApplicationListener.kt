package no.nav.security.token.support.spring.test

import java.net.ServerSocket
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.boot.context.event.ApplicationPreparedEvent
import org.springframework.context.ApplicationListener
import org.springframework.core.annotation.Order
import org.springframework.core.env.MapPropertySource
import org.springframework.core.env.MutablePropertySources

@Order
class MockOAuth2ServerApplicationListener : ApplicationListener<ApplicationPreparedEvent> {

    private val log : Logger = LoggerFactory.getLogger(MockOAuth2ServerApplicationListener::class.java)
    override fun onApplicationEvent(event : ApplicationPreparedEvent) =
        registerPort(event).also {
            log.debug("received ApplicationPreparedEvent, register random port with environment if ot set")
        }

    private fun registerPort(event : ApplicationPreparedEvent) {
        with(event.applicationContext.environment) {
            val port = getProperty(PORT_PROPERTY,Int::class.java)
            if (isRandomPort(port)) {
                with(propertySources) {
                    addPropertySource(this)
                    (get(PROPERTY_PREFIX) as MapPropertySource).source.apply {
                        put(PORT_PROPERTY, findAvailableTcpPort())
                        put(RANDOM_PORT_PROPERTY, true)
                        put("$PROPERTY_PREFIX.interactive-login", false)
                        log.debug("Registered property source {}", this)
                    }
                }
            }
            else {
                log.debug("port provided explicitly from annotation ({}), nothing to register.", port)
            }
        }

    }

    private fun findAvailableTcpPort() = ServerSocket(0).use { it.localPort }

    private fun isRandomPort(httpPortProperty: Int?) = httpPortProperty == null || httpPortProperty <= 0

    private fun addPropertySource(propertySources : MutablePropertySources) {
        if (!propertySources.contains(PROPERTY_PREFIX)) {
            propertySources.addFirst(
                MapPropertySource(PROPERTY_PREFIX, HashMap()))
        }
        else {
            val source = propertySources.remove(PROPERTY_PREFIX)!!
            propertySources.addFirst(source)
        }
    }

    companion object {

        private const val PROPERTY_PREFIX : String = MockOAuth2ServerProperties.PREFIX
        private const val PORT_PROPERTY = "$PROPERTY_PREFIX.port"
        private const val RANDOM_PORT_PROPERTY = "$PROPERTY_PREFIX.random-port"
    }
}