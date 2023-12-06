package no.nav.security.token.support.core.configuration;

import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import no.nav.security.token.support.core.IssuerMockWebServer;
import no.nav.security.token.support.core.exceptions.MetaDataNotAvailableException;
import no.nav.security.token.support.core.validation.DefaultConfigurableJwtValidator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.util.List;

import static java.util.Collections.emptyList;
import static no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IssuerConfigurationTest {

    private IssuerMockWebServer issuerMockWebServer;

    @BeforeEach
    void setup() throws IOException {
        issuerMockWebServer = new IssuerMockWebServer(false);
        issuerMockWebServer.start();
    }

    @AfterEach
    void after() throws IOException {
        issuerMockWebServer.shutdown();
    }

    @Test
    void issuerConfigurationWithMetadataFromDiscoveryUrl() {
        IssuerConfiguration config = new IssuerConfiguration(
            "issuer1", new IssuerProperties(issuerMockWebServer.getDiscoveryUrl(), List.of("audience1")), new ProxyAwareResourceRetriever());
        assertThat(config.getMetadata()).isNotNull();
        assertThat(config.getTokenValidator()).isNotNull();
        assertThat(config.getTokenValidator()).isInstanceOf(DefaultConfigurableJwtValidator.class);
        AuthorizationServerMetadata metadata = config.getMetadata();
        assertThat(metadata.getIssuer()).isNotNull();
        assertThat(metadata.getJWKSetURI().toString()).isNotNull();
    }

    @Test
    void issuerConfigurationDiscoveryUrlNotValid() {
        assertThatExceptionOfType(MetaDataNotAvailableException.class).isThrownBy(() -> new IssuerConfiguration(
            "issuer1",
            new IssuerProperties(URI.create("http://notvalid").toURL(), List.of("audience1")),
            new ProxyAwareResourceRetriever()));
        assertThatExceptionOfType(MetaDataNotAvailableException.class).isThrownBy(() -> new IssuerConfiguration(
            "issuer1",
            new IssuerProperties(URI.create("http://localhost").toURL(), List.of("audience1")),
            new ProxyAwareResourceRetriever()));
        assertThatExceptionOfType(MetaDataNotAvailableException.class).isThrownBy(() -> new IssuerConfiguration(
            "issuer1",
            new IssuerProperties(URI.create(issuerMockWebServer.getDiscoveryUrl().toString() + "/pathincorrect").toURL(),
                List.of("audience1")),
            new ProxyAwareResourceRetriever()));
    }

    @Test
    void issuerConfigurationWithConfigurableJwtTokenValidator() {
        IssuerProperties issuerProperties = new IssuerProperties(
            issuerMockWebServer.getDiscoveryUrl(), emptyList(),null,AUTHORIZATION_HEADER, new IssuerProperties.Validation(List.of("sub", "aud"))
        );
        IssuerConfiguration config = new IssuerConfiguration(
            "issuer1",
            issuerProperties,
            new ProxyAwareResourceRetriever()
        );
        assertThat(config.getMetadata()).isNotNull();
        assertThat(config.getTokenValidator()).isNotNull();
        assertThat(config.getTokenValidator()).isInstanceOf(DefaultConfigurableJwtValidator.class);
        AuthorizationServerMetadata metadata = config.getMetadata();
        assertThat(metadata.getIssuer()).isNotNull();
        assertThat(metadata.getJWKSetURI().toString()).isNotNull();
        assertTrue(issuerProperties.getValidation().isConfigured());
    }

    @Test
    void issuerConfigurationWithConfigurableJWKSCacheAndConfigurableJwtTokenValidator() {
        IssuerProperties issuerProperties = new IssuerProperties(
            issuerMockWebServer.getDiscoveryUrl(),emptyList(),null,AUTHORIZATION_HEADER,
            new IssuerProperties.Validation(List.of("sub", "aud")),
            new IssuerProperties.JwksCache(15L, 5L)
        );
        IssuerConfiguration config = new IssuerConfiguration(
            "issuer1",
            issuerProperties,
            new ProxyAwareResourceRetriever()
        );
        assertThat(config.getMetadata()).isNotNull();
        assertThat(config.getTokenValidator()).isNotNull();
        assertThat(config.getTokenValidator()).isInstanceOf(DefaultConfigurableJwtValidator.class);
        AuthorizationServerMetadata metadata = config.getMetadata();
        assertThat(metadata.getIssuer()).isNotNull();
        assertThat(metadata.getJWKSetURI().toString()).isNotNull();
        assertTrue(issuerProperties.getJwksCache().isConfigured());
        assertTrue(issuerProperties.getValidation().isConfigured());
    }
}