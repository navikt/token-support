package no.nav.security.token.support.core.validation;

import com.nimbusds.jose.jwk.source.DefaultJWKSetCache;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.ResourceRetriever;
import no.nav.security.token.support.core.configuration.IssuerProperties;

import java.net.URL;
import java.util.concurrent.TimeUnit;

public class RemoteJWKSetCache {
    private final IssuerProperties.JwksCache jwksCache;
    private final ResourceRetriever resourceRetriever;
    private final URL jwKsUrl;

    public RemoteJWKSetCache(IssuerProperties issuerProperties, ResourceRetriever resourceRetriever, URL jwKsUrl) {
        this.jwksCache = issuerProperties.getJwksCache();
        this.resourceRetriever = resourceRetriever;
        this.jwKsUrl = jwKsUrl;
    }

    public RemoteJWKSet<SecurityContext> configure() {
        return this.jwksCache.isConfigured() ? new RemoteJWKSet<>(
            jwKsUrl,
            resourceRetriever,
            new DefaultJWKSetCache(
                this.jwksCache.getLifespan(),
                this.jwksCache.getRefreshTime(),
                TimeUnit.MINUTES
            )
        ) : new RemoteJWKSet<>(jwKsUrl, resourceRetriever);
    }
}
