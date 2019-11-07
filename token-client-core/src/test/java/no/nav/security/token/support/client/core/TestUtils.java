package no.nav.security.token.support.client.core;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings("WeakerAccess")
public class TestUtils {

    public static final String CONTENT_TYPE_FORM_URL_ENCODED = "application/x-www-form-urlencoded;charset=UTF-8";
    public static final String CONTENT_TYPE_JSON = "application/json;charset=UTF-8";

    public static ClientProperties clientProperties(String tokenEndpointUrl, OAuth2GrantType oAuth2GrantType) {
        return ClientProperties.builder()
            .grantType(oAuth2GrantType)
            .scope(List.of("scope1", "scope2"))
            .tokenEndpointUrl(URI.create(tokenEndpointUrl))
            .authentication(ClientAuthenticationProperties.builder()
                .clientAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientId("client1")
                .clientSecret("clientSecret1")
                .build())
            .build();
    }

    public static MockResponse jsonResponse(String json) {
        return new MockResponse()
            .setHeader("Content-Type", "application/json;charset=UTF-8")
            .setBody(json);
    }

    public static void assertPostMethodAndJsonHeaders(RecordedRequest recordedRequest) {
        assertThat(recordedRequest.getMethod()).isEqualTo("POST");
        assertThat(recordedRequest.getHeader("Accept")).isEqualTo(CONTENT_TYPE_JSON);
        assertThat(recordedRequest.getHeader("Content-Type")).isEqualTo(CONTENT_TYPE_FORM_URL_ENCODED);
    }

    public static String decodeBasicAuth(RecordedRequest recordedRequest) {
        return Optional.ofNullable(recordedRequest.getHeaders().get("Authorization"))
            .map(s -> s.split("Basic "))
            .filter(pair -> pair.length == 2)
            .map(pair -> Base64.getDecoder().decode(pair[1]))
            .map(bytes -> new String(bytes, StandardCharsets.UTF_8))
            .orElse("");
    }

    public static JWT jwt(String sub) {
        Instant expiry = LocalDateTime.now().atZone(ZoneId.systemDefault()).plusSeconds(60).toInstant();
        return new PlainJWT(new JWTClaimsSet.Builder()
            .subject(sub)
            .audience("thisapi")
            .issuer("someIssuer")
            .expirationTime(Date.from(expiry))
            .claim("jti", UUID.randomUUID().toString())
            .build());
    }
}
