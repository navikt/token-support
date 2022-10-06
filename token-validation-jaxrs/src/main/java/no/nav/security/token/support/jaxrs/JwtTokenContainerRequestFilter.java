package no.nav.security.token.support.jaxrs;

import jakarta.inject.Inject;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import no.nav.security.token.support.core.exceptions.JwtTokenInvalidClaimException;
import no.nav.security.token.support.core.validation.JwtTokenAnnotationHandler;

import java.lang.reflect.Method;

@Provider
public class JwtTokenContainerRequestFilter implements ContainerRequestFilter {

    private final JwtTokenAnnotationHandler jwtTokenAnnotationHandler;

    @Context
    private ResourceInfo resourceInfo;

    @Inject
    public JwtTokenContainerRequestFilter() {
        this.jwtTokenAnnotationHandler = new JwtTokenAnnotationHandler(JaxrsTokenValidationContextHolder.getHolder());
    }

    @Override
    public void filter(ContainerRequestContext containerRequestContext) {
        Method method = resourceInfo.getResourceMethod();
        try {
            jwtTokenAnnotationHandler.assertValidAnnotation(method);
        } catch (JwtTokenInvalidClaimException e) {
            throw new WebApplicationException(e, Response.Status.FORBIDDEN);
        } catch (Exception e) {
            throw new WebApplicationException(e, Response.Status.UNAUTHORIZED);
        }
    }
}
