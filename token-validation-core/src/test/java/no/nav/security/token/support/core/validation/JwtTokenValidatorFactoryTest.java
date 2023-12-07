package no.nav.security.token.support.core.validation;


import com.nimbusds.jose.jwk.source.JWKSetBasedJWKSource;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.id.Issuer;
import no.nav.security.token.support.core.configuration.IssuerProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.List;

import static java.util.Collections.emptyList;
import static java.util.concurrent.TimeUnit.MINUTES;
import static no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER;
import static no.nav.security.token.support.core.validation.JwtTokenValidatorFactory.tokenValidator;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class JwtTokenValidatorFactoryTest {

    @Mock
    private AuthorizationServerMetadata metadata;
    @Mock
    private ResourceRetriever resourceRetriever;

    private IssuerProperties issuerProperties;
    private final URL url = new URL("http://url");

    JwtTokenValidatorFactoryTest() throws MalformedURLException {
    }

    @BeforeEach
    void setup() {
        issuerProperties = new IssuerProperties(url, List.of("aud1"));
        when(metadata.getJWKSetURI()).thenReturn(URI.create("http://someurl"));
        when(metadata.getIssuer()).thenReturn(new Issuer("myissuer"));
    }

    @Test
    void createDefaultTokenValidator() {
        var defaultValidator = tokenValidator(issuerProperties, metadata, resourceRetriever);
        assertThat(defaultValidator).isInstanceOf(DefaultConfigurableJwtValidator.class);

        var source = getJwkSource(defaultValidator);
        assertThat(source).isInstanceOf(JWKSetBasedJWKSource.class);

        var basedSource = ((JWKSetBasedJWKSource<?>) source);
        assertThat(basedSource.getJWKSetSource()).isInstanceOf(RefreshAheadCachingJWKSetSource.class);

        var cache = ((RefreshAheadCachingJWKSetSource<?>) basedSource.getJWKSetSource());
        assertThat(cache.getTimeToLive()).isEqualTo(MINUTES.toMillis(15));
        assertThat(cache.getCacheRefreshTimeout()).isEqualTo(MINUTES.toMillis(5));
    }

    @Test
    void createTokenValidatorWithOptionalClaim() {
        issuerProperties = new IssuerProperties(
            url,emptyList(),null,AUTHORIZATION_HEADER,
            new IssuerProperties.Validation(List.of("optionalclaim")),
            IssuerProperties.JwksCache.EMPTY_CACHE
        );
        var validatorWithDefaultCache = tokenValidator(issuerProperties, metadata, resourceRetriever);
        assertThat(validatorWithDefaultCache).isInstanceOf(DefaultConfigurableJwtValidator.class);
    }

    @Test
    void createTokenValidatorWithCustomJwksCache() {
        var jwksCacheProperties = new IssuerProperties.JwksCache(5L, 1L);
        issuerProperties = new IssuerProperties(
            url,emptyList(),null,AUTHORIZATION_HEADER,
            new IssuerProperties.Validation(List.of("optionalclaim")),
            jwksCacheProperties
        );

        var validatorWithCustomCache = tokenValidator(issuerProperties, metadata, resourceRetriever);
        assertThat(validatorWithCustomCache).isInstanceOf(DefaultConfigurableJwtValidator.class);

        var source = getJwkSource(validatorWithCustomCache);
        assertThat(source).isInstanceOf(JWKSetBasedJWKSource.class);

        var basedSource = ((JWKSetBasedJWKSource<?>) source);
        assertThat(basedSource.getJWKSetSource()).isInstanceOf(RefreshAheadCachingJWKSetSource.class);

        var cache = ((RefreshAheadCachingJWKSetSource<?>) basedSource.getJWKSetSource());
        assertThat(cache.getTimeToLive()).isEqualTo(jwksCacheProperties.getLifespanMillis());
        assertThat(cache.getCacheRefreshTimeout()).isEqualTo(jwksCacheProperties.getRefreshTimeMillis());
    }

    @Test
    void createTokenValidatorWithProvidedJwkSource() {
        var jwkSource = JWKSourceBuilder.create(url)
            .cache(MINUTES.toMillis(5), MINUTES.toMillis(1))
            .build();
        var jwtTokenValidator = tokenValidator(issuerProperties, metadata, jwkSource);
        assertThat(getJwkSource(jwtTokenValidator)).isEqualTo(jwkSource);
    }

    private static JWKSource<SecurityContext> getJwkSource(JwtTokenValidator jwtTokenValidator) {
        return ((DefaultConfigurableJwtValidator) jwtTokenValidator).getJwkSource();
    }
}