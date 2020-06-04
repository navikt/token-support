package no.nav.security.token.support.spring.test;

import no.nav.security.mock.oauth2.MockOAuth2Server;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@SpringBootTest(
    classes = TestApplication.class,
    properties = "discoveryUrl=http://localhost:${mock-oauth2-server.port}/test/.well-known/openid-configuration",
    webEnvironment = SpringBootTest.WebEnvironment.NONE)
@EnableMockOAuth2Server
class EnableMockOAuth2ServerRandomPortTest {

    @Autowired
    private MockOAuth2ServerProperties properties;

    @Autowired
    private MockOAuth2Server server;

    @Value("${discoveryUrl}")
    private String discoveryUrl;

    @Test
    public void serverStartsOnRandomPortAndIsUpdatedInEnv() {
        assertThat(server.baseUrl().port()).isEqualTo(properties.getPort());
        assertThat(server.wellKnownUrl("test").toString()).isEqualTo(discoveryUrl);
    }
}

