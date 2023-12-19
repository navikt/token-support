package no.nav.security.token.support.jaxrs

import jakarta.inject.Inject
import jakarta.ws.rs.WebApplicationException
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ContainerRequestFilter
import jakarta.ws.rs.container.ResourceInfo
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.Response.Status.FORBIDDEN
import jakarta.ws.rs.core.Response.Status.UNAUTHORIZED
import jakarta.ws.rs.ext.Provider
import no.nav.security.token.support.core.exceptions.JwtTokenInvalidClaimException
import no.nav.security.token.support.core.validation.JwtTokenAnnotationHandler
import no.nav.security.token.support.jaxrs.JaxrsTokenValidationContextHolder.getHolder

@Provider
class JwtTokenContainerRequestFilter @Inject constructor() : ContainerRequestFilter {

    private val jwtTokenAnnotationHandler = JwtTokenAnnotationHandler(getHolder())

    @Context
    private lateinit var resourceInfo : ResourceInfo

    override fun filter(containerRequestContext : ContainerRequestContext) {
        val method = resourceInfo.resourceMethod
        try {
            jwtTokenAnnotationHandler.assertValidAnnotation(method)
        }
        catch (e : JwtTokenInvalidClaimException) {
            throw WebApplicationException(e, FORBIDDEN)
        }
        catch (e : Exception) {
            throw WebApplicationException(e, UNAUTHORIZED)
        }
    }
}