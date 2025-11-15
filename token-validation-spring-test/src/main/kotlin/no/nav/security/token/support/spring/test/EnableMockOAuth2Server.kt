package no.nav.security.token.support.spring.test

import org.springframework.boot.test.context.PropertyMapping
import java.lang.annotation.Inherited
import org.springframework.context.annotation.Import
import kotlin.annotation.AnnotationRetention.RUNTIME
import kotlin.annotation.AnnotationTarget.CLASS

@MustBeDocumented
@Inherited
@Retention(RUNTIME)
@Target(CLASS)
@Import(MockOAuth2ServerAutoConfiguration::class, MockLoginController::class)
@PropertyMapping(MockOAuth2ServerProperties.PREFIX)
annotation class EnableMockOAuth2Server(
    /**
     * Specify port for server to run on (only works in test scope), provide via
     * env property mock-ouath2-server.port outside of test scope
     */
    val port : Int = 0)