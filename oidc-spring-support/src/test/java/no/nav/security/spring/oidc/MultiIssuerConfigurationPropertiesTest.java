package no.nav.security.spring.oidc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@TestPropertySource(locations={"/issuers.properties"})
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes={MultiIssuerProperties.class})
public class MultiIssuerConfigurationPropertiesTest {
	@Autowired
	private MultiIssuerProperties config;
	
	@Test
	public void test() {
		assertFalse(config.getIssuer().isEmpty());
		assertTrue(config.getIssuer().containsKey("number1"));
		assertEquals("http://metadata", config.getIssuer().get("number1").getDiscoveryUrl().toString());
		assertEquals("aud1", config.getIssuer().get("number1").getAcceptedAudience());
		assertEquals("idtoken", config.getIssuer().get("number1").getCookieName());
		assertTrue(config.getIssuer().containsKey("number2"));
		assertEquals("http://metadata2", config.getIssuer().get("number2").getDiscoveryUrl().toString());
		assertEquals("aud2", config.getIssuer().get("number2").getAcceptedAudience());
		assertEquals(null, config.getIssuer().get("number2").getCookieName());
		
	}

}
