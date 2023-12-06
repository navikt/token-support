package no.nav.security.token.support.core.configuration;

import com.nimbusds.jose.util.DefaultResourceRetriever;
import no.nav.security.token.support.core.IssuerMockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.Map;

import static no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER;
import static org.assertj.core.api.Assertions.assertThat;

class MultiIssuerConfigurationTest {
    private static final Logger log = LoggerFactory.getLogger(MultiIssuerConfigurationTest.class);
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
        IssuerProperties issuerProperties = new IssuerProperties(discoveryUrl, List.of("audience1"),null,AUTHORIZATION_HEADER, IssuerProperties.Validation.EMPTY, IssuerProperties.JwksCache.EMPTY_CACHE, proxyUrl);
        //issuerProperties.setProxyUrl(proxyUrl);
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
        assertThat(config.getMetadata()).isNotNull();
        assertThat(config.getMetadata().getIssuer()).isNotNull();
        assertThat(config.getMetadata().getIssuer().getValue()).isEqualTo("$ISSUER");
        assertThat(config.getResourceRetriever()).isNotNull();
    }
}