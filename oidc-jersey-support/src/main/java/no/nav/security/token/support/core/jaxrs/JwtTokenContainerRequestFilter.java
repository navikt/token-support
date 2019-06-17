package no.nav.security.token.support.core.jaxrs;

import no.nav.security.token.support.core.exceptions.JwtTokenInvalidClaimException;
import no.nav.security.token.support.core.validation.JwtTokenAnnotationHandler;

import javax.inject.Inject;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.lang.reflect.Method;

@Provider
public class JwtTokenContainerRequestFilter implements ContainerRequestFilter {

    private final JwtTokenAnnotationHandler jwtTokenAnnotationHandler;
    private final ResourceInfo resourceInfo;

    @Inject
    public JwtTokenContainerRequestFilter(@Context ResourceInfo resourceInfo) {
        this.resourceInfo = resourceInfo;
        this.jwtTokenAnnotationHandler = new JwtTokenAnnotationHandler(JaxrsTokenValidationContextHolder.getHolder());
    }

    @Override
    public void filter(ContainerRequestContext containerRequestContext) {
        Method method = resourceInfo.getResourceMethod();
        try {
            jwtTokenAnnotationHandler.assertValidAnnotation(method);
        } catch (JwtTokenInvalidClaimException e){
            throw new WebApplicationException(e, Response.Status.FORBIDDEN);
        } catch (Exception e) {
            throw new WebApplicationException(e, Response.Status.UNAUTHORIZED);
        }
    }
}
