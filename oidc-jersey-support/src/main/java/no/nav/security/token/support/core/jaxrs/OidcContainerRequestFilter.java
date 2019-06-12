package no.nav.security.token.support.core.jaxrs;

import no.nav.security.token.support.core.api.Protected;
import no.nav.security.token.support.core.api.ProtectedWithClaims;
import no.nav.security.token.support.core.api.Unprotected;
import no.nav.security.token.support.core.context.JwtTokenClaims;
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

        no.nav.security.token.support.core.context.JwtTokenValidationContext validationContext = JaxrsJwtTokenContextHolder.getHolder().getOIDCValidationContext();

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

        throw new WebApplicationException("Server misconfigured - controller/method ["
                    + resourceInfo.getResourceClass().getName() + "." + resourceInfo.getResourceMethod().getName()
                    + "] not annotated @Unprotected, @Protected or added to ignore list",
                Response.Status.UNAUTHORIZED); // TODO Should not leak information about implementation


    }

    private <T extends Annotation> T getMethodAnnotation(Class<T> annotation) {

        return resourceInfo.getResourceMethod().getDeclaredAnnotation(annotation);
    }

    private void handleProtectedAnnotation(no.nav.security.token.support.core.context.JwtTokenValidationContext validationContext) {

        if (!validationContext.hasValidToken()) {
            logger.info("No token found in validation context");
            throw new WebApplicationException("Authorization token required", Response.Status.UNAUTHORIZED);
        }
    }

    private void handleProtectedWithClaimsAnnotation(no.nav.security.token.support.core.context.JwtTokenValidationContext validationContext,
                                                     ProtectedWithClaims annotation) {
        String issuer = annotation.issuer();
        String[] claims = annotation.claimMap();
        if (StringUtils.isNotBlank(issuer)) {
            JwtTokenClaims tokenClaims = validationContext.getClaims(issuer);
            if (tokenClaims == null) {
                logger.info(String.format(
                        "could not find token for issuer '%s' in validation context. check your configuration.",
                        issuer));
                throw new WebApplicationException("Authorization token not authorized", Response.Status.UNAUTHORIZED);
            }
            if (!containsRequiredClaims(tokenClaims, annotation.combineWithOr(), claims)) {
                logger.info("token does not contain all annotated claims");
                throw new WebApplicationException("Authorization token not authorized", Response.Status.FORBIDDEN);
            }
        }
    }

    protected boolean containsRequiredClaims(JwtTokenClaims tokenClaims, boolean combineWithOr, String... claims){
        logger.debug("choose matching logic based on combineWithOr=" + combineWithOr);
        return combineWithOr ? containsAnyClaim(tokenClaims,claims)
                : containsAllClaims(tokenClaims, claims);
    }

    protected boolean containsAllClaims(JwtTokenClaims tokenClaims, String... claims) {
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

    protected boolean containsAnyClaim(JwtTokenClaims tokenClaims, String... claims){
        if(claims != null && claims.length > 0){
            for (String string : claims) {
                String name = StringUtils.substringBefore(string, "=").trim();
                String value = StringUtils.substringAfter(string, "=").trim();
                if (StringUtils.isNotBlank(name)) {
                    if (tokenClaims.containsClaim(name, value)) {
                        return true;
                    }
                }
            }
            logger.debug("token does not contain any of the listed claims");
            return false;
        }
        logger.debug("no claims listed, so claim checking is ok.");
        return true;
    }

}
