package no.nav.security.token.support.client.core.oauth2;

import no.nav.security.token.support.client.core.*;
import no.nav.security.token.support.client.core.auth.ClientAssertion;
import no.nav.security.token.support.client.core.http.OAuth2HttpClient;
import no.nav.security.token.support.client.core.http.OAuth2HttpHeaders;
import no.nav.security.token.support.client.core.http.OAuth2HttpRequest;

import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.*;

abstract class AbstractOAuth2TokenClient<T extends AbstractOAuth2GrantRequest> {

    private static final String CONTENT_TYPE_FORM_URL_ENCODED = "application/x-www-form-urlencoded;charset=UTF-8";
    private static final String CONTENT_TYPE_JSON = "application/json;charset=UTF-8";
    private final OAuth2HttpClient oAuth2HttpClient;

    AbstractOAuth2TokenClient(OAuth2HttpClient oAuth2HttpClient) {
        this.oAuth2HttpClient = oAuth2HttpClient;
    }

    OAuth2AccessTokenResponse getTokenResponse(T grantRequest) {

        var clientProperties = Optional.ofNullable(grantRequest)
            .map(AbstractOAuth2GrantRequest::getClientProperties)
            .orElseThrow(() -> new OAuth2ClientException("ClientProperties cannot be null"));

        try {
            var formParameters = createDefaultFormParameters(grantRequest);
            formParameters.putAll(this.formParameters(grantRequest));

            var oAuth2HttpRequest = OAuth2HttpRequest.builder()
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
        var headers = new HashMap<String, List<String>>();
        headers.put("Accept", List.of(CONTENT_TYPE_JSON));
        headers.put("Content-Type", Collections.singletonList(CONTENT_TYPE_FORM_URL_ENCODED));
        var auth = clientProperties.getAuthentication();
        if (CLIENT_SECRET_BASIC.equals(auth.getClientAuthMethod())) {
            headers.put("Authorization",
                List.of("Basic " + basicAuth(auth.getClientId(), auth.getClientSecret())));
        }
        return headers;
    }

    Map<String, String> createDefaultFormParameters(T grantRequest) {
        ClientProperties clientProperties = grantRequest.getClientProperties();
        Map<String, String> formParameters = new LinkedHashMap<>(clientAuthenticationFormParameters(grantRequest));
        formParameters.put(OAuth2ParameterNames.GRANT_TYPE, grantRequest.getGrantType().value());
        if (!clientProperties.getGrantType().equals(OAuth2GrantType.TOKEN_EXCHANGE)) {
            formParameters.put(OAuth2ParameterNames.SCOPE, String.join(" ", clientProperties.getScope()));
        }
        return formParameters;
    }

    private Map<String, String> clientAuthenticationFormParameters(T grantRequest) {
        ClientProperties clientProperties = grantRequest.getClientProperties();
        Map<String, String> formParameters = new LinkedHashMap<>();
        ClientAuthenticationProperties auth = clientProperties.getAuthentication();
        if (CLIENT_SECRET_POST.equals(auth.getClientAuthMethod())) {
            formParameters.put(OAuth2ParameterNames.CLIENT_ID, auth.getClientId());
            formParameters.put(OAuth2ParameterNames.CLIENT_SECRET, auth.getClientSecret());

        } else if (PRIVATE_KEY_JWT.equals(auth.getClientAuthMethod())) {
            ClientAssertion clientAssertion = new ClientAssertion(clientProperties.getTokenEndpointUrl(), auth);

            formParameters.put(OAuth2ParameterNames.CLIENT_ID, auth.getClientId());
            formParameters.put(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, clientAssertion.assertionType());
            formParameters.put(OAuth2ParameterNames.CLIENT_ASSERTION, clientAssertion.assertion());
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

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [oAuth2HttpClient=" + oAuth2HttpClient + "]";
    }
}
