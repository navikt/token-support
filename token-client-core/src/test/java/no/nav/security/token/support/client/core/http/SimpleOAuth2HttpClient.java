package no.nav.security.token.support.client.core.http;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse;

import java.io.IOException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
public class SimpleOAuth2HttpClient implements OAuth2HttpClient {

    private final ObjectMapper objectMapper;

    public SimpleOAuth2HttpClient() {
        this.objectMapper = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }


    @Override
    public OAuth2AccessTokenResponse post(OAuth2HttpRequest oAuth2HttpRequest) {
        try {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder();

            oAuth2HttpRequest.getOAuth2HttpHeaders().headers().forEach((key, value) -> value.forEach(v -> requestBuilder.header(key, v)));

            String body = oAuth2HttpRequest.getFormParameters().entrySet().stream()
                .map(entry -> entry.getKey() + "=" + URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));

            HttpRequest httpRequest = requestBuilder
                .uri(oAuth2HttpRequest.getTokenEndpointUrl())
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

            HttpResponse<String> response =
                HttpClient.newHttpClient().send(httpRequest, HttpResponse.BodyHandlers.ofString());

            return objectMapper.readValue(bodyAsString(response), OAuth2AccessTokenResponse.class);
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private String bodyAsString(HttpResponse<String> response){
        if(response != null){
            log.debug("received response in client, body={}", response.body());
            return Optional.of(response)
                .filter(r -> r.statusCode() == 200)
                .map(HttpResponse::body)
                .orElseThrow(() ->
                    new RuntimeException("received status code=" + response.statusCode()
                        + " and response body=" + response.body() + " from authorization server."));
        }
        throw new RuntimeException("response cannot be null.");
    }
}
