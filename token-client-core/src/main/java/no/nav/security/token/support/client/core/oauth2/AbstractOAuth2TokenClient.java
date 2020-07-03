package no.nav.security.token.support.client.core.oauth2;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import no.nav.security.token.support.client.core.*;
import no.nav.security.token.support.client.core.auth.ClientAssertion;
import no.nav.security.token.support.client.core.http.OAuth2HttpClient;
import no.nav.security.token.support.client.core.http.OAuth2HttpHeaders;
import no.nav.security.token.support.client.core.http.OAuth2HttpRequest;

import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

abstract class AbstractOAuth2TokenClient<T extends AbstractOAuth2GrantRequest> {

    private static final String CONTENT_TYPE_FORM_URL_ENCODED = "application/x-www-form-urlencoded;charset=UTF-8";
    private static final String CONTENT_TYPE_JSON = "application/json;charset=UTF-8";
    private final OAuth2HttpClient oAuth2HttpClient;

    AbstractOAuth2TokenClient(OAuth2HttpClient oAuth2HttpClient) {
        this.oAuth2HttpClient = oAuth2HttpClient;
    }

    OAuth2AccessTokenResponse getTokenResponse(T grantRequest) {

        ClientProperties clientProperties = Optional.ofNullable(grantRequest)
            .map(AbstractOAuth2GrantRequest::getClientProperties)
            .orElseThrow(() -> new OAuth2ClientException("ClientProperties cannot be null"));

        try {
            Map<String, String> formParameters = createDefaultFormParameters(grantRequest);
            formParameters.putAll(this.formParameters(grantRequest));

            OAuth2HttpRequest oAuth2HttpRequest = OAuth2HttpRequest.builder()
                .tokenEndpointUrl(clientProperties.getTokenEndpointUrl())
                .oAuth2HttpHeaders(OAuth2HttpHeaders.of(tokenRequestHeaders(clientProperties)))
                .formParameters(formParameters)
                .build();
            return oAuth2HttpClient.post(oAuth2HttpRequest);
        } catch (Exception e) {
            if (!(e instanceof OAuth2ClientException)) {
                throw new OAuth2ClientException(String.format("received exception %s when invoking tokenendpoint=%s",
                    e, grantRequest.getClientProperties().getTokenEndpointUrl()), e);
            }
            throw e;
        }
    }

    private Map<String, List<String>> tokenRequestHeaders(ClientProperties clientProperties) {
        Map<String, List<String>> headers = new HashMap<>();
        headers.put("Accept", Collections.singletonList(CONTENT_TYPE_JSON));
        headers.put("Content-Type", Collections.singletonList(CONTENT_TYPE_FORM_URL_ENCODED));
        ClientAuthenticationProperties auth = clientProperties.getAuthentication();
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(auth.getClientAuthMethod())) {
            headers.put("Authorization",
                Collections.singletonList("Basic "
                    + basicAuth(auth.getClientId(), auth.getClientSecret())));
        }
        return headers;
    }

    Map<String, String> createDefaultFormParameters(T grantRequest) {
        ClientProperties clientProperties = grantRequest.getClientProperties();
        Map<String, String> formParameters = new LinkedHashMap<>(clientAuthenticationFormParameters(grantRequest));
        formParameters.put(OAuth2ParameterNames.GRANT_TYPE, grantRequest.getGrantType().getValue());
        if (!clientProperties.getGrantType().equals(OAuth2GrantType.TOKEN_EXCHANGE)) {
            formParameters.put(OAuth2ParameterNames.SCOPE, String.join(" ", clientProperties.getScope()));
        }
        return formParameters;
    }

    private Map<String, String> clientAuthenticationFormParameters(T grantRequest) {
        ClientProperties clientProperties = grantRequest.getClientProperties();
        Map<String, String> formParameters = new LinkedHashMap<>();
        ClientAuthenticationProperties auth = clientProperties.getAuthentication();
        if (ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(auth.getClientAuthMethod())) {
            formParameters.put(OAuth2ParameterNames.CLIENT_ID, auth.getClientId());
            formParameters.put(OAuth2ParameterNames.CLIENT_SECRET, auth.getClientSecret());

        } else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.equals(auth.getClientAuthMethod())) {
            ClientAssertion clientAssertion = new ClientAssertion(clientProperties.getTokenEndpointUrl(), auth);

            formParameters.put(OAuth2ParameterNames.CLIENT_ID, auth.getClientId());
            formParameters.put(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, clientAssertion.assertionType());
            formParameters.put(OAuth2ParameterNames.CLIENT_ASSERTION, clientAssertion.assertion());

            if (clientProperties.getGrantType().equals(OAuth2GrantType.TOKEN_EXCHANGE)) {
                ExchangeProperties exchangeProperties = clientProperties.getTokenExchange();
                formParameters.put(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, exchangeProperties.subjectTokenType());
                formParameters.put(OAuth2ParameterNames.SUBJECT_TOKEN, exchangeProperties.getSubjectToken());
                formParameters.put(OAuth2ParameterNames.AUDIENCE, exchangeProperties.getAudience());
                if (exchangeProperties.getResource() != null && !exchangeProperties.getResource().isEmpty()) {
                    formParameters.put(OAuth2ParameterNames.RESOURCE, exchangeProperties.getResource());
                }
            }
        }
        return formParameters;
    }

    private String basicAuth(String username, String password) {
        Charset charset = StandardCharsets.UTF_8;
        CharsetEncoder encoder = charset.newEncoder();
        if (encoder.canEncode(username) && encoder.canEncode(password)) {
            String credentialsString = username + ":" + password;
            byte[] encodedBytes = Base64.getEncoder().encode(credentialsString.getBytes(StandardCharsets.UTF_8));
            return new String(encodedBytes, StandardCharsets.UTF_8);
        } else {
            throw new IllegalArgumentException("Username or password contains characters that cannot be encoded to " + charset.displayName());
        }
    }

    protected abstract Map<String, String> formParameters(T grantRequest);
}
