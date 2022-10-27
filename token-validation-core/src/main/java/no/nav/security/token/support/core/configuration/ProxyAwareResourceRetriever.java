package no.nav.security.token.support.core.configuration;

import com.nimbusds.jose.util.DefaultResourceRetriever;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.*;
import java.util.Arrays;
import java.util.Optional;

import static java.net.Proxy.Type.HTTP;

public class ProxyAwareResourceRetriever extends DefaultResourceRetriever {

    public static final int DEFAULT_HTTP_CONNECT_TIMEOUT = 21050;
    public static final int DEFAULT_HTTP_READ_TIMEOUT = 30000;
    public static final int DEFAULT_HTTP_SIZE_LIMIT = 50 * 1024;
    private static final Logger LOG = LoggerFactory.getLogger(ProxyAwareResourceRetriever.class);
    private final boolean usePlainTextForHttps;
    public ProxyAwareResourceRetriever() {
        this(null);
    }

    public ProxyAwareResourceRetriever(URL proxyUrl) {
        this(proxyUrl, false);
    }

    public ProxyAwareResourceRetriever(URL proxyUrl, boolean usePlainTextForHttps) {
        this(proxyUrl, usePlainTextForHttps, DEFAULT_HTTP_CONNECT_TIMEOUT, DEFAULT_HTTP_READ_TIMEOUT, DEFAULT_HTTP_SIZE_LIMIT);
    }

    ProxyAwareResourceRetriever(URL proxyUrl, boolean usePlainTextForHttps, int connectTimeout, int readTimeout, int sizeLimit) {
        super(connectTimeout, readTimeout, sizeLimit);
        this.usePlainTextForHttps = usePlainTextForHttps;
        setProxy(proxyFrom(proxyUrl));
    }

    URL urlWithPlainTextForHttps(URL url) throws IOException {
        try {
            URI uri = url.toURI();
            if (!uri.getScheme().equals("https")) {
                return url;
            }
            int port = url.getPort() > 0 ? url.getPort() : 443;
            String newUrl = "http://" + uri.getHost() + ":" + port + uri.getPath()
                + (uri.getQuery() != null && uri.getQuery().length() > 0 ? "?" + uri.getQuery() : "");
            LOG.debug("using plaintext connection for https url, new url is {}", newUrl);
            return URI.create(newUrl).toURL();
        } catch (URISyntaxException e) {
            throw new IOException(e);
        }
    }

    @Override
    protected HttpURLConnection openConnection(URL url) throws IOException {
        var urlToOpen = usePlainTextForHttps ? urlWithPlainTextForHttps(url) : url;
        if (shouldProxy(url)) {
            LOG.trace("Connecting to {} via proxy {}",urlToOpen,getProxy());
            return (HttpURLConnection)urlToOpen.openConnection(getProxy());
        }
        LOG.trace("Connecting to {} without proxy",urlToOpen);
        return (HttpURLConnection)urlToOpen.openConnection();
    }

    boolean shouldProxy(URL url) {
        return getProxy() != null && !isNoProxy(url);
    }

    private boolean isNoProxy(URL url) {
        var noProxy = System.getenv("NO_PROXY");
        var isNoProxy =  Optional.ofNullable(noProxy)
            .map(s -> Arrays.stream(s.split(","))
                .anyMatch(url.toString()::contains)).orElse(false);
        if (noProxy != null && isNoProxy) {
            LOG.trace("Not using proxy for {} since it is covered by the NO_PROXY setting {}",url,noProxy);
        } else {
            LOG.trace("Using proxy for {} since it is not  covered by the NO_PROXY setting {}",url,noProxy);
        }
        return isNoProxy;
    }

    private static Proxy proxyFrom(URL proxyUrl) {
        return Optional.ofNullable(proxyUrl)
            .map(u -> new Proxy(HTTP, new InetSocketAddress(u.getHost(), u.getPort())))
            .orElse(null);
    }
}
