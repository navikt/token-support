package no.nav.security.token.support.core.configuration;

import com.nimbusds.jose.util.BoundedInputStream;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jose.util.Resource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.nio.charset.Charset;

public class ProxyAwareResourceRetriever extends DefaultResourceRetriever {

    public static final int DEFAULT_HTTP_CONNECT_TIMEOUT = 21050;
    public static final int DEFAULT_HTTP_READ_TIMEOUT = 30000;
    public static final int DEFAULT_HTTP_SIZE_LIMIT = 50 * 1024;
    private static final Logger logger = LoggerFactory.getLogger(ProxyAwareResourceRetriever.class);
    private final URL proxyUrl;
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
        this.proxyUrl = proxyUrl;
        this.usePlainTextForHttps = usePlainTextForHttps;
    }

    @Override
    public Resource retrieveResource(URL url) throws IOException {
        logger.debug("attempting to getStringClaim resource {}", url);
        HttpURLConnection con = null;
        try {
            con = openConnection(url);
            con.setConnectTimeout(getConnectTimeout());
            con.setReadTimeout(getReadTimeout());
            final String content;
            InputStream inputStream = con.getInputStream();
            try {
                if (getSizeLimit() > 0) {
                    inputStream = new BoundedInputStream(inputStream, getSizeLimit());
                }
                content = IOUtils.readInputStreamToString(inputStream, Charset.forName("UTF-8"));
            } finally {
                inputStream.close();
            }

            int statusCode = con.getResponseCode();
            String statusMessage = con.getResponseMessage();
            // Ensure 2xx status code
            if (statusCode > 299 || statusCode < 200) {
                throw new IOException("HTTP " + statusCode + ": " + statusMessage);
            }
            return new Resource(content, con.getContentType());
        } catch (ClassCastException | URISyntaxException e) {
            throw new IOException("Couldn't open HTTP(S) connection: " + e.getMessage(), e);
        } finally {
            if (disconnectsAfterUse() && con != null) {
                con.disconnect();
            }
        }
    }

    private boolean isUsePlainTextForHttps() {
        return usePlainTextForHttps;
    }

    URL urlWithPlainTextForHttps(URL url) throws MalformedURLException, URISyntaxException {
        URI uri = url.toURI();
        if (!uri.getScheme().equals("https")) {
            return url;
        }
        int port = url.getPort() > 0 ? url.getPort() : 443;
        String newUrl = "http://" + uri.getHost() + ":" + port + uri.getPath()
                + (uri.getQuery() != null && uri.getQuery().length() > 0 ? "?" + uri.getQuery() : "");
        logger.debug("using plaintext connection for https url, new url is {}", newUrl);
        return URI.create(newUrl).toURL();
    }

    private Proxy getProxy() {
        return proxyUrl != null ?
            new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyUrl.getHost(), proxyUrl.getPort()))
            : null;
    }

    private HttpURLConnection openConnection(URL url) throws IOException, URISyntaxException {
        Proxy proxy = getProxy();
        URL urlToOpen = isUsePlainTextForHttps() ? urlWithPlainTextForHttps(url) : url;
        return proxy == null ?
            (HttpURLConnection) urlToOpen.openConnection() : (HttpURLConnection) urlToOpen.openConnection(proxy);
    }
}
