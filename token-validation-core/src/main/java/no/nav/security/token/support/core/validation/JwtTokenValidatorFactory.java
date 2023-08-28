package no.nav.security.token.support.core.validation;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import no.nav.security.token.support.core.configuration.IssuerProperties;
import no.nav.security.token.support.core.exceptions.MetaDataNotAvailableException;

import java.net.MalformedURLException;
import java.net.URL;

public class JwtTokenValidatorFactory {

    private JwtTokenValidatorFactory() {

    }

    public static JwtTokenValidator tokenValidator(
        IssuerProperties issuerProperties,
        AuthorizationServerMetadata metadata,
        ResourceRetriever resourceRetriever
    ) {
        return tokenValidator(issuerProperties, metadata, jwkSource(
            issuerProperties,
            getJWKsUrl(metadata),
            resourceRetriever
        ));
    }

    public static JwtTokenValidator tokenValidator(
        IssuerProperties issuerProperties,
        AuthorizationServerMetadata metadata,
        JWKSource<SecurityContext> remoteJWKSet
    ) {
        return new DefaultConfigurableJwtValidator(
            metadata.getIssuer().getValue(),
            issuerProperties.getAcceptedAudience(),
            issuerProperties.getValidation().getOptionalClaims(),
            remoteJWKSet
        );
    }

    private static JWKSource<SecurityContext> jwkSource(
        IssuerProperties issuerProperties,
        URL jwksUrl,
        ResourceRetriever resourceRetriever
    ) {
        var jwkSource = JWKSourceBuilder.create(jwksUrl, resourceRetriever);

        if (issuerProperties.getJwksCache().isConfigured()) {
            jwkSource.cache(
                issuerProperties.getJwksCache().getLifespanMillis(),
                issuerProperties.getJwksCache().getRefreshTimeMillis()
            );
        }

        return jwkSource.build();
    }

    private static URL getJWKsUrl(AuthorizationServerMetadata metaData) {
        try {
            return metaData.getJWKSetURI().toURL();
        } catch (MalformedURLException e) {
            throw new MetaDataNotAvailableException(e);
        }
    }
}
