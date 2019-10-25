package no.nav.security.token.support.client.core.http;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OAuth2HttpHeadersTest {

    @Test
    void test() {
        OAuth2HttpHeaders httpHeadersFromBuilder = OAuth2HttpHeaders.builder()
            .header("header1", "header1value1")
            .header("header1", "header1value2")
            .build();
        OAuth2HttpHeaders httpHeadersFromOf = OAuth2HttpHeaders.of(Map.of("header1", List.of("header1value1",
            "header1value2")));
        assertThat(httpHeadersFromBuilder).isEqualTo(httpHeadersFromOf);
        assertThat(httpHeadersFromBuilder.headers()).hasSize(1);
        assertThat(httpHeadersFromBuilder.headers()).isEqualTo(httpHeadersFromOf.headers());
    }
}
