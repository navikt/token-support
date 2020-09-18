package no.nav.security.token.support.core.configuration;

import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import no.nav.security.token.support.core.IssuerMockWebServer;
import no.nav.security.token.support.core.exceptions.MetaDataNotAvailableException;
import no.nav.security.token.support.core.validation.ConfigurableJwtTokenValidator;
import no.nav.security.token.support.core.validation.DefaultJwtTokenValidator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

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
        assertThat(config.getMetaData()).isNotNull();
        assertThat(config.getTokenValidator()).isNotNull();
        assertThat(config.getTokenValidator() instanceof DefaultJwtTokenValidator);
        AuthorizationServerMetadata metadata = config.getMetaData();
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
        IssuerConfiguration config = new IssuerConfiguration(
            "issuer1",
            new IssuerProperties(
                issuerMockWebServer.getDiscoveryUrl(),
                new IssuerProperties.Validation(List.of("sub", "aud"))
            ),
            new ProxyAwareResourceRetriever()
        );
        assertThat(config.getMetaData()).isNotNull();
        assertThat(config.getTokenValidator()).isNotNull();
        assertThat(config.getTokenValidator() instanceof ConfigurableJwtTokenValidator);
        AuthorizationServerMetadata metadata = config.getMetaData();
        assertThat(metadata.getIssuer()).isNotNull();
        assertThat(metadata.getJWKSetURI().toString()).isNotNull();
    }
}
