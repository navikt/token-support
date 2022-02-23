package no.nav.security.token.support.core.configuration;

import com.nimbusds.jose.util.DefaultResourceRetriever;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.*;

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
        if (proxyUrl != null) {
            setProxy(new Proxy(HTTP, new InetSocketAddress(proxyUrl.getHost(), proxyUrl.getPort())));
        }
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
        URL urlToOpen = usePlainTextForHttps ? urlWithPlainTextForHttps(url) : url;
        return super.openConnection(urlToOpen);
    }
}
