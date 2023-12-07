package no.nav.security.token.support.core;

import com.nimbusds.jose.util.IOUtils;
import okhttp3.*;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okio.BufferedSink;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class IssuerMockWebServer {
    private static final Logger log = LoggerFactory.getLogger(IssuerMockWebServer.class);
    private static final String DISCOVERY_PATH = "/.well-known/openid-configuration";
    private MockWebServer server;
    private MockWebServer proxyServer;
    private URL discoveryUrl;
    private URL proxyUrl;
    private final boolean startProxyServer;

    public IssuerMockWebServer() {
        this(true);
    }

    public IssuerMockWebServer(boolean startProxyServer) {
        this.startProxyServer = startProxyServer;
    }

    public void start() throws IOException {
        this.server = new MockWebServer();
        this.server.start();
        this.discoveryUrl = this.server.url(DISCOVERY_PATH).url();
        this.server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(@NotNull RecordedRequest request) {
                log.debug("received request on url={} with headers={}", request.getRequestUrl(), request.getHeaders());
                log.debug("comparing path in request '{}' with '{}'", request.getRequestUrl().encodedPath(),
                    DISCOVERY_PATH);
                if (request.getRequestUrl().encodedPath().endsWith(DISCOVERY_PATH)) {
                    log.debug("returning well-known json data");
                    return wellKnownJson();
                } else {
                    log.error("path not found, returning 404");
                    return new MockResponse().setResponseCode(404);
                }
            }
        });

        this.proxyServer = new MockWebServer();
        this.proxyServer.setDispatcher(new ProxyDispatcher(HttpUrl.parse(discoveryUrl.toString())));
        if (startProxyServer) {
            this.proxyServer.start();
            this.proxyUrl = URI.create("http://localhost:" + this.proxyServer.getPort()).toURL();
        }
    }

    public void shutdown() throws IOException {
        server.shutdown();
        proxyServer.shutdown();
    }

    public URL getDiscoveryUrl() {
        return discoveryUrl;
    }

    public URL getProxyUrl() {
        return proxyUrl;
    }

    private static MockResponse mockResponse(String json) {
        return new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json;charset=UTF-8")
            .setBody(json);
    }

    private static MockResponse wellKnownJson() {
        try {
            String json = IOUtils.readInputStreamToString(
                IssuerMockWebServer.class.getResourceAsStream("/metadata.json"), StandardCharsets.UTF_8);
            return mockResponse(json);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public MockWebServer getServer() {
        return this.server;
    }

    public MockWebServer getProxyServer() {
        return this.proxyServer;
    }

    public boolean isStartProxyServer() {
        return this.startProxyServer;
    }

    public void setServer(MockWebServer server) {
        this.server = server;
    }

    public void setProxyServer(MockWebServer proxyServer) {
        this.proxyServer = proxyServer;
    }

    public void setDiscoveryUrl(URL discoveryUrl) {
        this.discoveryUrl = discoveryUrl;
    }

    public void setProxyUrl(URL proxyUrl) {
        this.proxyUrl = proxyUrl;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IssuerMockWebServer that = (IssuerMockWebServer) o;
        return startProxyServer == that.startProxyServer &&
            Objects.equals(server, that.server) &&
            Objects.equals(proxyServer, that.proxyServer) &&
            Objects.equals(discoveryUrl, that.discoveryUrl) &&
            Objects.equals(proxyUrl, that.proxyUrl);
    }

    @Override
    public int hashCode() {
        return Objects.hash(server, proxyServer, discoveryUrl, proxyUrl, startProxyServer);
    }

    public String toString() {
        return "IssuerMockWebServer(server=" + this.getServer() + ", proxyServer=" + this.getProxyServer() + ", discoveryUrl=" + this.getDiscoveryUrl() + ", proxyUrl=" + this.getProxyUrl() + ", startProxyServer=" + this.isStartProxyServer() + ")";
    }

    static class ProxyDispatcher extends Dispatcher {
        private final OkHttpClient client;
        private final HttpUrl serverUrl;

        ProxyDispatcher(HttpUrl url) {
            serverUrl = url;
            client = new OkHttpClient.Builder().build();
        }

        @Override
        public MockResponse dispatch(final RecordedRequest recordedRequest) {
            Request.Builder requestBuilder = new Request.Builder()
                .url(serverUrl)
                .headers(recordedRequest.getHeaders())
                .removeHeader("Host");

            if (recordedRequest.getBodySize() != 0) {
                requestBuilder.method(recordedRequest.getMethod(), new RequestBody() {
                    @Override
                    public MediaType contentType() {
                        return MediaType.parse(recordedRequest.getHeader("Content-Type"));
                    }

                    @Override
                    public void writeTo(BufferedSink sink) throws IOException {
                        recordedRequest.getBody().clone().readAll(sink);
                    }

                    @Override
                    public long contentLength() {
                        return recordedRequest.getBodySize();
                    }
                });
            }
            Request request = requestBuilder.build();
            log.debug("created request to destination: {}", request);
            try (Response response = client.newCall(request).execute()) {
                ResponseBody body = response.body();
                if (body != null) {
                    MockResponse mockResponse = new MockResponse();
                    mockResponse.headers(response.headers());
                    mockResponse.setBody(body.string());
                    mockResponse.setResponseCode(response.code());
                    return mockResponse;
                } else {
                    MockResponse mockResponse = new MockResponse();
                    mockResponse.status("proxy error, response body from destination was null");
                    mockResponse.setResponseCode(500);
                    return mockResponse;
                }
            } catch (IOException e) {
                log.error("got exception when proxying request.", e);
                MockResponse mockResponse = new MockResponse();
                mockResponse.status("proxy error: " + e.getMessage());
                mockResponse.setResponseCode(500);
                return mockResponse;
            }
        }
    }
}