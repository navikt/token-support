package no.nav.security.token.support.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@TestPropertySource(locations = { "/issuers.properties" })
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = { MultiIssuerProperties.class })
public class MultiIssuerConfigurationPropertiesTest {
    @Autowired
    private MultiIssuerProperties config;

    @Test
    public void test() {
        assertFalse(config.getIssuer().isEmpty());

        assertTrue(config.getIssuer().containsKey("number1"));
        assertEquals("http://metadata", config.getIssuer().get("number1").getDiscoveryUrl().toString());
        assertTrue(config.getIssuer().get("number1").getAcceptedAudience().contains("aud1"));
        assertEquals("idtoken", config.getIssuer().get("number1").getCookieName());

        assertTrue(config.getIssuer().containsKey("number2"));
        assertEquals("http://metadata2", config.getIssuer().get("number2").getDiscoveryUrl().toString());
        assertTrue(config.getIssuer().get("number2").getAcceptedAudience().contains("aud2"));
        assertEquals(null, config.getIssuer().get("number2").getCookieName());

        assertTrue(config.getIssuer().containsKey("number3"));
        assertEquals("http://metadata3", config.getIssuer().get("number3").getDiscoveryUrl().toString());
        assertTrue(config.getIssuer().get("number3").getAcceptedAudience().contains("aud3")
                && config.getIssuer().get("number3").getAcceptedAudience().contains("aud4"));

        assertTrue(config.getIssuer().containsKey("number4"));
        assertEquals("http://metadata4", config.getIssuer().get("number4").getDiscoveryUrl().toString());
        assertTrue(config.getIssuer().get("number4").isConfigurableClaimValidator());
    }

}
