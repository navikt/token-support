package no.nav.security.spring.oidc.test;

/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import java.io.IOException;
import java.nio.charset.Charset;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.IOUtils;

import no.nav.security.oidc.http.HttpClient;
import no.nav.security.oidc.http.HttpHeaders;

public class JsonFileHttpClient implements HttpClient {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final String metadataFile;
    private final String jwksFile;

    public JsonFileHttpClient(String metadataFile, String jwksFile) {
        this.metadataFile = metadataFile;
        this.jwksFile = jwksFile;
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T> T get(String uri, HttpHeaders headers, Class<T> clazz) {
        try {
            if (uri.contains("metadata")) {
                return JSON.readValue(this.getClass().getResourceAsStream(metadataFile), clazz);
            }
            if (uri.contains("jwks")) {
                String s = IOUtils.readInputStreamToString(this.getClass().getResourceAsStream(jwksFile),
                        Charset.forName("UTF-8"));
                System.out.println("content in metadata: " + s);
                return (T) s;
            }
            return null;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public <T> T post(String uri, String body, HttpHeaders headers, Class<T> clazz) {
        return null;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [metadataFile=" + metadataFile + ", jwksFile=" + jwksFile + "]";
    }
}
