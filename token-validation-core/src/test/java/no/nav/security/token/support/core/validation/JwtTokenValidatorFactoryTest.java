package no.nav.security.token.support.core.validation;


import com.nimbusds.jose.jwk.source.DefaultJWKSetCache;
import com.nimbusds.jose.jwk.source.JWKSetCache;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
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
import java.util.List;
import java.util.concurrent.TimeUnit;

import static com.nimbusds.jose.jwk.source.DefaultJWKSetCache.DEFAULT_LIFESPAN_MINUTES;
import static com.nimbusds.jose.jwk.source.DefaultJWKSetCache.DEFAULT_REFRESH_TIME_MINUTES;
import static no.nav.security.token.support.core.validation.JwtTokenValidatorFactory.tokenValidator;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class JwtTokenValidatorFactoryTest {

    @Mock
    private RemoteJWKSet<SecurityContext> remoteJWKSet;
    @Mock
    private AuthorizationServerMetadata metadata;
    @Mock
    private ResourceRetriever resourceRetriever;

    private IssuerProperties issuerProperties;

    @BeforeEach
    void setup() throws MalformedURLException {
        issuerProperties = new IssuerProperties(
            URI.create("http://url").toURL(),
            List.of("aud1")
        );
        when(metadata.getJWKSetURI()).thenReturn(URI.create("http://someurl"));
        when(metadata.getIssuer()).thenReturn(new Issuer("myissuer"));
    }

    @Test
    void testCreateDefaultJwtTokenValidator() {
        assertThat(tokenValidator(issuerProperties, metadata, resourceRetriever))
            .isInstanceOf(DefaultJwtTokenValidator.class);
    }

    @Test
    void testCreateConfigurableJwtTokenValidator() {
        issuerProperties.setValidation(new IssuerProperties.Validation(List.of("optionalclaim")));
        var validatorWithDefaultCache = tokenValidator(issuerProperties, metadata, resourceRetriever);
        assertThat(validatorWithDefaultCache).isInstanceOf(ConfigurableJwtTokenValidator.class);
    }

    @Test
    void testCreateJwtTokenValidatorWithDefaultCacheValues() {
        var validatorWithDefaultCache = tokenValidator(issuerProperties, metadata, resourceRetriever);
        assertThat(validatorWithDefaultCache).isInstanceOf(DefaultJwtTokenValidator.class);
        var cache = getCache(validatorWithDefaultCache);
        assertThat(cache).isInstanceOf(DefaultJWKSetCache.class);
        assertThat(((DefaultJWKSetCache) cache).getLifespan(TimeUnit.MINUTES)).isEqualTo(DEFAULT_LIFESPAN_MINUTES);
        assertThat(((DefaultJWKSetCache) cache).getRefreshTime(TimeUnit.MINUTES)).isEqualTo(DEFAULT_REFRESH_TIME_MINUTES);
    }

    @Test
    void testCreateJwtTokenValidatorWithCustomCacheValues() {
        issuerProperties.setJwksCache(new IssuerProperties.JwksCache(1L, 2L));
        var validatorWithCustomCache = tokenValidator(issuerProperties, metadata, resourceRetriever);
        assertThat(validatorWithCustomCache).isInstanceOf(DefaultJwtTokenValidator.class);
        var cache = getCache(validatorWithCustomCache);
        assertThat(cache).isInstanceOf(DefaultJWKSetCache.class);
        assertThat(((DefaultJWKSetCache) cache).getLifespan(TimeUnit.MINUTES)).isEqualTo(1L);
        assertThat(((DefaultJWKSetCache) cache).getRefreshTime(TimeUnit.MINUTES)).isEqualTo(2L);
    }

    @Test
    void testCreateValidatorWithProvidedRemoteJWKSet() {
        var jwtTokenValidator = tokenValidator(issuerProperties, metadata, remoteJWKSet);
        var cache = new DefaultJWKSetCache(1L, 2L, TimeUnit.MINUTES);
        when(remoteJWKSet.getJWKSetCache()).thenReturn(cache);
        assertThat(getCache(jwtTokenValidator)).isEqualTo(cache);
    }

    private static JWKSetCache getCache(JwtTokenValidator jwtTokenValidator) {
        return jwtTokenValidator instanceof ConfigurableJwtTokenValidator ?
            ((ConfigurableJwtTokenValidator) jwtTokenValidator).getRemoteJWKSet().getJWKSetCache() :
            ((DefaultJwtTokenValidator) jwtTokenValidator).getRemoteJWKSet().getJWKSetCache();
    }
}
