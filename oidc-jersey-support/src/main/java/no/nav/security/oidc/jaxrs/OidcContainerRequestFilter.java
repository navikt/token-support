package no.nav.security.oidc.jaxrs;

import no.nav.security.oidc.api.Protected;
import no.nav.security.oidc.api.ProtectedWithClaims;
import no.nav.security.oidc.api.Unprotected;
import no.nav.security.oidc.context.OIDCClaims;
import no.nav.security.oidc.context.OIDCValidationContext;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.lang.annotation.Annotation;

@Provider
public class OidcContainerRequestFilter implements ContainerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(OidcContainerRequestFilter.class);

    private final ResourceInfo resourceInfo;

    @Inject
    public OidcContainerRequestFilter(@Context ResourceInfo resourceInfo) {

        this.resourceInfo = resourceInfo;
    }

    @Override
    public void filter(ContainerRequestContext containerRequestContext) {

        OIDCValidationContext validationContext = OidcRequestContext.getHolder().getOIDCValidationContext();

        Unprotected unprotectedAnnotation = getMethodAnnotation(Unprotected.class);
        if (unprotectedAnnotation != null) {
            logger.debug("method " + resourceInfo.getResourceMethod() + " marked @Unprotected");
            return;
        }
        ProtectedWithClaims withClaimsAnnotation = getMethodAnnotation(ProtectedWithClaims.class);
        if (withClaimsAnnotation != null) {
            logger.debug("method " + resourceInfo.getResourceMethod() + " marked @ProtectedWithClaims");
            handleProtectedWithClaimsAnnotation(validationContext, withClaimsAnnotation);
            return;
        } else {
            Protected protectedAnnotation = getMethodAnnotation(Protected.class);
            if (protectedAnnotation != null) {
                logger.debug("method " + resourceInfo.getResourceMethod() + " marked @Protected");
                handleProtectedAnnotation(validationContext);
                return;
            }
        }

        Class<?> declaringClass = resourceInfo.getResourceClass();
        if (declaringClass.isAnnotationPresent(Unprotected.class)) {
            logger.debug("method " + resourceInfo.getResourceMethod() + " marked @Unprotected throug annotation on class");
            return;
        }

        if (declaringClass.isAnnotationPresent(ProtectedWithClaims.class)) {
            logger.debug("method " + resourceInfo.getResourceMethod() + " marked @ProtectedWithClaims");
            handleProtectedWithClaimsAnnotation(validationContext,
                    declaringClass.getAnnotation(ProtectedWithClaims.class));
            return;
        } else {
            if (declaringClass.isAnnotationPresent(Protected.class)) {
                logger.debug("method " + resourceInfo.getResourceMethod() + " marked @Protected");
                handleProtectedAnnotation(validationContext);
                return;
            }
        }
        logger.debug("method " + resourceInfo.getResourceMethod() + " not marked, access denied (returning NOT_IMPLEMENTED)");

        // TODO throw proper exception
        throw new WebApplicationException("Server misconfigured - controller/method ["
                    + resourceInfo.getResourceClass().getName() + "." + resourceInfo.getResourceMethod().getName()
                    + "] not annotated @Unprotected, @Protected or added to ignore list",
                Response.Status.UNAUTHORIZED); // TODO Should not leak information about implementation


    }

    private <T extends Annotation> T getMethodAnnotation(Class<T> annotation) {

        return resourceInfo.getResourceMethod().getDeclaredAnnotation(annotation);
    }

    private void handleProtectedAnnotation(OIDCValidationContext validationContext) {

        if (!validationContext.hasValidToken()) {
            logger.error("no token found in validation context");
            throw new WebApplicationException("Authorization token required", Response.Status.UNAUTHORIZED);
        }
    }

    private void handleProtectedWithClaimsAnnotation(OIDCValidationContext validationContext,
                                                          ProtectedWithClaims annotation) {
        String issuer = annotation.issuer();
        String[] claims = annotation.claimMap();
        if (StringUtils.isNotBlank(issuer)) {
            OIDCClaims tokenClaims = validationContext.getClaims(issuer);
            if (tokenClaims == null) {
                logger.error(String.format(
                        "could not find token for issuer '%s' in validation context. check your configuration.",
                        issuer));
                throw new WebApplicationException("Authorization token not authorized", Response.Status.UNAUTHORIZED);
                //throw new OIDCUnauthorizedException("Authorization token not authorized");
            }
            if (!containsRequiredClaims(tokenClaims, claims)) {
                logger.error("token does not contain all annotated claims");
                throw new WebApplicationException("Authorization token not authorized", Response.Status.FORBIDDEN);
                //throw new OIDCUnauthorizedException("Authorization token not authorized");
            }
        }
    }

    private boolean containsRequiredClaims(OIDCClaims tokenClaims, String... claims) {
        for (String string : claims) {
            String name = StringUtils.substringBefore(string, "=").trim();
            String value = StringUtils.substringAfter(string, "=").trim();
            if (StringUtils.isNotBlank(name)) {
                if (!tokenClaims.containsClaim(name, value)) {
                    logger.debug(String.format("token does not contain %s = %s", name, value));
                    return false;
                }
            }
        }
        return true;
    }

}
