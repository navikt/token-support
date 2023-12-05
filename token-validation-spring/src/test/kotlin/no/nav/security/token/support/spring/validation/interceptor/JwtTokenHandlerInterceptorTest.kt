package no.nav.security.token.support.spring.validation.interceptor

import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.PlainJWT
import net.minidev.json.JSONArray
import no.nav.security.token.support.core.api.Protected
import no.nav.security.token.support.core.api.ProtectedWithClaims
import no.nav.security.token.support.core.api.Unprotected
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.jwt.JwtToken
import org.assertj.core.api.Assertions.assertThatExceptionOfType
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.core.annotation.AnnotationAttributes.fromMap
import org.springframework.http.HttpStatus.NOT_IMPLEMENTED
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.web.method.HandlerMethod
import org.springframework.web.server.ResponseStatusException
import java.util.concurrent.ConcurrentHashMap
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import no.nav.security.token.support.core.utils.Cluster

internal class JwtTokenHandlerInterceptorTest {
    private val contextHolder  = createContextHolder()
    private lateinit var interceptor: JwtTokenHandlerInterceptor
    private val request: MockHttpServletRequest = MockHttpServletRequest()
    private val response: MockHttpServletResponse = MockHttpServletResponse()

    @BeforeEach
    fun setup() {
        val annotationAttributesMap: MutableMap<String, Any> = HashMap()
        annotationAttributesMap["ignore"] = arrayOf("org.springframework", IgnoreClass::class.java.name)
        interceptor = JwtTokenHandlerInterceptor(fromMap(annotationAttributesMap), SpringJwtTokenAnnotationHandler(contextHolder))
    }

    @Test
    fun classIsMarkedAsIgnore() = assertTrue(interceptor.preHandle(request, response, handlerMethod(IgnoreClass(), "test")))


    @Test
    fun notAnnotatedShouldThrowException() {
        assertThatExceptionOfType(ResponseStatusException::class.java).isThrownBy {
            interceptor.preHandle(request, response, handlerMethod(NotAnnotatedClass(), "test"))
        }.withMessageContaining(NOT_IMPLEMENTED.toString())
    }

    @Test
    fun methodIsUnprotectedAccessShouldBeAllowed() = assertTrue(interceptor.preHandle(request, response, handlerMethod(UnprotectedClass(), "test")))


    @Test
    fun methodShouldBeProtected() {
        val handlerMethod = handlerMethod(ProtectedClass(), "test")
        assertThrows(JwtTokenUnauthorizedException::class.java) { interceptor.preHandle(request, response, handlerMethod) }
        setupValidOidcContext()
        assertTrue(interceptor.preHandle(request, response, handlerMethod))
    }
    @Test
    fun methodExcludedShouldNotThrow() {
        val handlerMethod = handlerMethod(ProtectedClass(), "test")
        assertThrows(JwtTokenUnauthorizedException::class.java) { interceptor.preHandle(request, response, handlerMethod) }
        setupValidOidcContext()
        assertTrue(interceptor.preHandle(request, response, handlerMethod))
    }

    @Test
    fun methodShouldBeProtectedOnUnprotectedClass() {
        val handlerMethod = handlerMethod(UnprotectedClassProtectedMethod(), "protectedMethod")
        assertThrows(JwtTokenUnauthorizedException::class.java) { interceptor.preHandle(request, response, handlerMethod) }
        setupValidOidcContext()
        assertTrue(interceptor.preHandle(request, response, handlerMethod))
    }

    @Test
    fun methodShouldBeUnprotectedOnProtectedClass() = assertTrue(interceptor.preHandle(request, response, handlerMethod(ProtectedClassUnprotectedMethod(), "unprotectedMethod")))

    @Test
    fun methodShouldBeProtectedWithClaims() {
        val handlerMethod = handlerMethod(ProtectedClassProtectedWithClaimsMethod(), "protectedMethod")
        assertThrows(JwtTokenUnauthorizedException::class.java) { interceptor.preHandle(request, response, handlerMethod) }
        setupValidOidcContext()
        assertTrue(interceptor.preHandle(request, response, handlerMethod))
    }

    @Test
    fun excludedMethodShouldBeOK() {
        val handlerMethod = handlerMethod(ProtectedClassProtectedWithClaimsMethod(), "protectedExcludedMethod")
        assertTrue(interceptor.preHandle(request, response, handlerMethod))
    }

    @Test
    fun methodShouldBeProtectedOnClassProtectedWithClaims() {
        val handlerMethod = handlerMethod(ProtectedWithClaimsClassProtectedMethod(), "protectedMethod")
        assertThrows(JwtTokenUnauthorizedException::class.java) { interceptor.preHandle(request, response, handlerMethod) }
        setupValidOidcContext()
        assertTrue(interceptor.preHandle(request, response, handlerMethod))
    }
    @Test
    fun methodShouldBeProtectedOnClassProtectedWithClaimsButExcluded() {
        val handlerMethod = handlerMethod(ProtectedWithClaimsCButExcludedClassProtectedMethod(), "protectedMethod")
        assertThrows(JwtTokenUnauthorizedException::class.java) { interceptor.preHandle(request, response, handlerMethod) }
        setupValidOidcContext()
        assertTrue(interceptor.preHandle(request, response, handlerMethod))
    }

    @Test
    fun methodShouldBeExcludedOnClassProtectedWithClaimsButExcluded() {
        val handlerMethod = handlerMethod(ProtectedWithClaimsCButExcludedClassProtectedMethod(), "protectedWithClaimsMethod")
        assertTrue(interceptor.preHandle(request, response, handlerMethod))
    }

    @Test
    fun methodIsUnprotectedAccessShouldBeAllowedMeta() = assertTrue(interceptor.preHandle(request, response, handlerMethod(UnprotectedClassMeta(), "test")))

    @Test
    fun methodShouldBeProtectedOnUnprotectedClassMeta() {
        val handlerMethod = handlerMethod(UnprotectedClassProtectedMethodMeta(), "protectedMethod")
        assertThrows(JwtTokenUnauthorizedException::class.java) { interceptor.preHandle(request, response, handlerMethod) }
        setupValidOidcContext()
        assertTrue(interceptor.preHandle(request, response, handlerMethod))
    }

    @Test
    fun methodShouldBeUnprotectedOnProtectedClassMeta() = assertTrue(interceptor.preHandle(request, response, handlerMethod(ProtectedClassUnprotectedMethodMeta(), "unprotectedMethod")))


    @Test
    fun methodShouldBeProtectedOnProtectedSuperClassMeta() {
        val handlerMethod = handlerMethod(ProtectedSubClassMeta(), "test")
        assertThrows(JwtTokenUnauthorizedException::class.java) { interceptor.preHandle(request, response, handlerMethod) }
        setupValidOidcContext()
        assertTrue(interceptor.preHandle(request, response, handlerMethod))
    }

    @Test
    fun unprotectedMetaClassProtectedMethodMeta() {
        val handlerMethod = handlerMethod(UnprotectedClassProtectedMethodMeta(), "protectedMethod")
        assertThrows(JwtTokenUnauthorizedException::class.java) { interceptor.preHandle(request, response, handlerMethod) }
        setupValidOidcContext()
        assertTrue(interceptor.preHandle(request, response, handlerMethod))
    }

    @Test
    fun methodShouldBeProtectedOnClassProtectedWithClaimsMeta() {
        val handlerMethod = handlerMethod(ProtectedWithClaimsClassProtectedMethodMeta(), "protectedMethod")
        assertThrows(JwtTokenUnauthorizedException::class.java) { interceptor.preHandle(request, response, handlerMethod) }
        setupValidOidcContext()
        assertTrue(interceptor.preHandle(request, response, handlerMethod))
    }

    private fun setupValidOidcContext() {
        contextHolder.setTokenValidationContext(createOidcValidationContext("issuer1", createJwtToken("aclaim", "value")))
    }

    private inner class IgnoreClass {
        fun test() {}
    }

    private inner class NotAnnotatedClass {
        fun test() {}
    }

    @Unprotected
    private inner class UnprotectedClass {
        fun test() {}
    }

    @Protected
    private inner class ProtectedClass {
        fun test() {}
    }

    @Protected
    private inner class ProtectedClassUnprotectedMethod {
        fun protectedMethod() {}

        @Unprotected
        fun unprotectedMethod() {
        }
    }

    @Unprotected
    private inner class UnprotectedClassProtectedMethod {
        @Protected
        fun protectedMethod() {
        }

        fun unprotectedMethod() {}
    }

    @Protected
    private inner class ProtectedClassProtectedWithClaimsMethod {
        @ProtectedWithClaims(issuer = "issuer1")
        fun protectedMethod() {
        }
        @ProtectedWithClaims(issuer = "issuer1", excludedClusters = [Cluster.LOCAL])
        fun protectedExcludedMethod() {
        }

        @Unprotected
        fun unprotectedMethod() {
        }

        fun unprotected() {}
    }

    @ProtectedWithClaims(issuer = "issuer1")
    private inner class ProtectedWithClaimsClassProtectedMethod {
        @Protected
        fun protectedMethod() {
        }

        @Unprotected
        fun unprotectedMethod() {
        }

        fun protectedWithClaimsMethod() {}
    }
    @ProtectedWithClaims(issuer = "issuer1",excludedClusters = [Cluster.LOCAL])
    private inner class ProtectedWithClaimsCButExcludedClassProtectedMethod {
        @Protected
        fun protectedMethod() {
        }

        @Unprotected
        fun unprotectedMethod() {
        }

        fun protectedWithClaimsMethod() {}
    }

    @UnprotectedMeta
    private inner class UnprotectedClassMeta {
        fun test() {}
    }

    @UnprotectedMeta
    private inner class UnprotectedClassProtectedMethodMeta {
        @ProtectedMeta
        fun protectedMethod() {
        }
    }

    @ProtectedMeta
    private inner class ProtectedClassMeta {
        fun test() {}
    }

    @ProtectedMeta
    private open inner class ProtectedSuperClassMeta
    private inner class ProtectedSubClassMeta : ProtectedSuperClassMeta() {
        fun test() {}
    }

    @ProtectedMeta
    private inner class ProtectedClassUnprotectedMethodMeta {
        fun protectedMethod() {}

        @UnprotectedMeta
        fun unprotectedMethod() {
        }
    }

    @ProtectedWithClaimsMeta
    private inner class ProtectedWithClaimsClassProtectedMethodMeta {
        @ProtectedMeta
        fun protectedMethod() {
        }

        @UnprotectedMeta
        fun unprotectedMethod() {
        }

        fun protectedWithClaimsMethod() {}
    }

    companion object {
        private fun createOidcValidationContext(issuerShortName: String, jwtToken: JwtToken): TokenValidationContext {
            val map: MutableMap<String, JwtToken> = ConcurrentHashMap()
            map[issuerShortName] = jwtToken
            return TokenValidationContext(map)
        }

        private fun createJwtToken(claimName: String, claimValue: String): JwtToken {
            val groupsValues = JSONArray()
            groupsValues.add("123")
            groupsValues.add("456")
            return JwtToken(
                    PlainJWT(
                            Builder()
                                .subject("subject")
                                .issuer("http//issuer1")
                                .claim("acr", "Level4")
                                .claim("groups", groupsValues)
                                .claim(claimName, claimValue).build()).serialize())
        }

        private fun createContextHolder(): TokenValidationContextHolder {
            return object : TokenValidationContextHolder {
                var validationContext: TokenValidationContext = TokenValidationContext(emptyMap())
                override fun getTokenValidationContext(): TokenValidationContext {
                    return validationContext
                }

                override fun setTokenValidationContext(tokenValidationContext: TokenValidationContext?) {
                    validationContext = tokenValidationContext?: TokenValidationContext(emptyMap())
                }
            }
        }

        private fun handlerMethod(`object`: Any, method: String): HandlerMethod {
            return try {
                HandlerMethod(`object`, method)
            } catch (e: NoSuchMethodException) {
                throw RuntimeException(e)
            }
        }
    }
}