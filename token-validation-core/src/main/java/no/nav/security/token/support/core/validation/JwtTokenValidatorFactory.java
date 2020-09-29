package no.nav.security.token.support.core.validation;

import com.nimbusds.jose.jwk.source.DefaultJWKSetCache;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import no.nav.security.token.support.core.configuration.IssuerProperties;
import no.nav.security.token.support.core.exceptions.MetaDataNotAvailableException;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.concurrent.TimeUnit;


public class JwtTokenValidatorFactory {

    public static JwtTokenValidator tokenValidator(
        IssuerProperties issuerProperties,
        AuthorizationServerMetadata metadata,
        ResourceRetriever resourceRetriever
    ) {
        RemoteJWKSet<SecurityContext> remoteJWKSet = remoteJwkSet(
            issuerProperties,
            getJWKsUrl(metadata),
            resourceRetriever
        );
        return tokenValidator(issuerProperties, metadata, remoteJWKSet);
    }

    public static JwtTokenValidator tokenValidator(
        IssuerProperties issuerProperties,
        AuthorizationServerMetadata metadata,
        RemoteJWKSet<SecurityContext> remoteJWKSet
    ) {
        if (issuerProperties.getValidation().isConfigured()) {
            return new ConfigurableJwtTokenValidator(
                metadata.getIssuer().getValue(),
                issuerProperties.getValidation().getOptionalClaims(),
                remoteJWKSet
            );
        } else {
            return new DefaultJwtTokenValidator(
                metadata.getIssuer().getValue(),
                issuerProperties.getAcceptedAudience(),
                remoteJWKSet
            );
        }
    }

    private static RemoteJWKSet<SecurityContext> remoteJwkSet(
        IssuerProperties issuerProperties,
        URL jwksUrl,
        ResourceRetriever resourceRetriever
    ) {
        return issuerProperties.getJwksCache().isConfigured() ?
            new RemoteJWKSet<>(
                jwksUrl,
                resourceRetriever,
                new DefaultJWKSetCache(
                    issuerProperties.getJwksCache().getLifespan(),
                    issuerProperties.getJwksCache().getRefreshTime(),
                    TimeUnit.MINUTES
                )
            ) : new RemoteJWKSet<>(jwksUrl, resourceRetriever);
    }

    private static URL getJWKsUrl(AuthorizationServerMetadata metaData) {
        try {
            return metaData.getJWKSetURI().toURL();
        } catch (MalformedURLException e) {
            throw new MetaDataNotAvailableException(e);
        }
    }
}
