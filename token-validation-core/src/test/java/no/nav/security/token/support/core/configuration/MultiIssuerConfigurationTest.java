package no.nav.security.token.support.core.configuration;

import com.nimbusds.jose.util.DefaultResourceRetriever;
import lombok.extern.slf4j.Slf4j;
import no.nav.security.token.support.core.IssuerMockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
class MultiIssuerConfigurationTest {
    private IssuerMockWebServer issuerMockWebServer;
    private URL discoveryUrl;
    private URL proxyUrl;

    @BeforeEach
    void setup() throws IOException {
        this.issuerMockWebServer = new IssuerMockWebServer();
        this.issuerMockWebServer.start();
        this.discoveryUrl = issuerMockWebServer.getDiscoveryUrl();
        this.proxyUrl = issuerMockWebServer.getProxyUrl();
    }

    @AfterEach
    void teardown() throws IOException {
        this.issuerMockWebServer.shutdown();
    }

    @Test
    void getIssuerConfiguration() {
        IssuerProperties issuerProperties = new IssuerProperties(discoveryUrl, List.of("audience1"));
        String issuerName = "issuer1";
        MultiIssuerConfiguration multiIssuerConfiguration =
            new MultiIssuerConfiguration(Map.of(issuerName, issuerProperties));
        assertThatMultiIssuerConfigurationIsPopulatedFromMetadata(issuerName, multiIssuerConfiguration);
    }

    @Test
    void getIssuerConfigurationWithProxy() {
        IssuerProperties issuerProperties = new IssuerProperties(discoveryUrl, List.of("audience1"));
        issuerProperties.setProxyUrl(proxyUrl);
        String issuerName = "issuer1";
        MultiIssuerConfiguration multiIssuerConfiguration =
            new MultiIssuerConfiguration(Map.of(issuerName, issuerProperties));

        assertThatMultiIssuerConfigurationIsPopulatedFromMetadata(issuerName, multiIssuerConfiguration);
        IssuerConfiguration config = multiIssuerConfiguration.getIssuer(issuerName).orElse(null);
        assertThat(config).isNotNull();
        assertThat(config.getResourceRetriever()).isInstanceOf(DefaultResourceRetriever.class);
        assertThat(((DefaultResourceRetriever) config.getResourceRetriever()).getProxy()).isNotNull();
    }

    private void assertThatMultiIssuerConfigurationIsPopulatedFromMetadata(String issuerName,
                                                                           MultiIssuerConfiguration multiIssuerConfiguration) {
        assertThat(multiIssuerConfiguration.getIssuerShortNames()).containsExactly(issuerName);
        IssuerConfiguration config = multiIssuerConfiguration.getIssuer(issuerName).orElse(null);
        assertThat(config).isNotNull();
        assertThat(config.getName()).isEqualTo(issuerName);
        assertThat(config.getTokenValidator()).isNotNull();
        assertThat(config.getMetaData()).isNotNull();
        assertThat(config.getMetaData().getIssuer()).isNotNull();
        assertThat(config.getMetaData().getIssuer().getValue()).isEqualTo("$ISSUER");
        assertThat(config.getResourceRetriever()).isNotNull();
    }
}


