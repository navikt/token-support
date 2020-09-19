package no.nav.security.token.support.core.configuration;

import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import lombok.Getter;
import lombok.ToString;
import no.nav.security.token.support.core.exceptions.MetaDataNotAvailableException;
import no.nav.security.token.support.core.validation.ConfigurableJwtTokenValidator;
import no.nav.security.token.support.core.validation.DefaultJwtTokenValidator;
import no.nav.security.token.support.core.validation.JwtTokenValidator;
import no.nav.security.token.support.core.validation.RemoteJWKSetCache;

import java.net.MalformedURLException;
import java.net.URL;

@Getter
@ToString
public class ValidationConfiguration {

    private final IssuerProperties issuerProperties;
    private final AuthorizationServerMetadata metaData;
    private final RemoteJWKSetCache remoteJWKSetCache;
    private final JwtTokenValidator jwtTokenValidator;

    ValidationConfiguration(AuthorizationServerMetadata metaData, ResourceRetriever resourceRetriever, IssuerProperties issuerProperties) {
        this.issuerProperties = issuerProperties;
        this.metaData = metaData;
        this.remoteJWKSetCache = new RemoteJWKSetCache(issuerProperties, resourceRetriever, getJWKsUrl(metaData));
        this.jwtTokenValidator = createTokenValidator();
    }

    protected JwtTokenValidator createTokenValidator() {
        if (issuerProperties.getValidation().isConfigured()) {
            return new ConfigurableJwtTokenValidator(
                metaData.getIssuer().getValue(),
                issuerProperties.getValidation().getOptionalClaims(),
                remoteJWKSetCache.configure()
            );
        } else {
            return new DefaultJwtTokenValidator(
                metaData.getIssuer().getValue(),
                issuerProperties.getAcceptedAudience(),
                remoteJWKSetCache.configure()
            );
        }
    }

    private static URL getJWKsUrl(AuthorizationServerMetadata metaData) {
        try {
            return metaData.getJWKSetURI().toURL();
        } catch (MalformedURLException e) {
            throw new MetaDataNotAvailableException(e);
        }
    }
}
