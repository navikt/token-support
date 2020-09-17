package no.nav.security.token.support.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

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
        assertNull(config.getIssuer().get("number2").getCookieName());

        assertTrue(config.getIssuer().containsKey("number3"));
        assertEquals("http://metadata3", config.getIssuer().get("number3").getDiscoveryUrl().toString());
        assertTrue(config.getIssuer().get("number3").getAcceptedAudience().contains("aud3")
                && config.getIssuer().get("number3").getAcceptedAudience().contains("aud4"));

        assertTrue(config.getIssuer().containsKey("number4"));
        assertEquals("http://metadata4", config.getIssuer().get("number4").getDiscoveryUrl().toString());

        assertThat(config.getIssuer().get("number4").getValidation().getOptionalClaims()).containsExactly(
            "sub",
            "aud"
        );

        assertTrue(config.getIssuer().containsKey("number5"));
        assertEquals("http://metadata5", config.getIssuer().get("number5").getDiscoveryUrl().toString());
        System.out.println(config.getIssuer().toString());
        assertEquals(10L, config.getIssuer().get("number5").getJwkSetCache().getLifespan());
        assertEquals(5L, config.getIssuer().get("number5").getJwkSetCache().getRefreshTime());
    }

}
