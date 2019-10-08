package no.nav.security.token.support.oauth2.client;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class TestUtils {
    static String createJwt() {
        Instant expiry = LocalDateTime.now().atZone(ZoneId.systemDefault()).plusSeconds(60).toInstant();
        JWT jwt = new PlainJWT(new JWTClaimsSet.Builder()
            .subject("someUser")
            .audience("thisapi")
            .issuer("someIssuer")
            .expirationTime(Date.from(expiry))
            .claim("jti", UUID.randomUUID().toString())
            .build());
        return jwt.serialize();
    }

    static MockResponse jsonResponse(String json) {
        return new MockResponse()
            .setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .setBody(json);
    }

    static void assertPostMethodAndJsonHeaders(RecordedRequest recordedRequest) {
        assertThat(recordedRequest.getMethod()).isEqualTo(HttpMethod.POST.toString());
        assertThat(recordedRequest.getHeader(HttpHeaders.ACCEPT)).isEqualTo(MediaType.APPLICATION_JSON_UTF8_VALUE);
        assertThat(recordedRequest.getHeader(HttpHeaders.CONTENT_TYPE)).isEqualTo(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8");
    }

    static OAuth2AccessTokenResponse accessTokenResponse(String assertion, int expiresIn){
        return new OAuth2AccessTokenResponse() {
            @Override
            public String getAccessToken() {
                return assertion;
            }

            @Override
            public int getExpiresAt() {
                return Math.toIntExact((Instant.now().plusSeconds(expiresIn).getEpochSecond()));
            }

            @Override
            public int getExpiresIn() {
                return expiresIn;
            }
        };
    }
}
