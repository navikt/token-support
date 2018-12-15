package no.nav.security.oidc.configuration;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.util.BoundedInputStream;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jose.util.Resource;

//TODO Could need some love
public class OIDCResourceRetriever extends DefaultResourceRetriever {

    public static int DEFAULT_HTTP_CONNECT_TIMEOUT = 21050;
    public static int DEFAULT_HTTP_READ_TIMEOUT = 30000;
    public static int DEFAULT_HTTP_SIZE_LIMIT = 50 * 1024;

    private Logger logger = LoggerFactory.getLogger(OIDCResourceRetriever.class);
    private URL proxyUrl;
    private boolean usePlainTextForHttps = false;

    public OIDCResourceRetriever() {
        this(DEFAULT_HTTP_CONNECT_TIMEOUT, DEFAULT_HTTP_READ_TIMEOUT, DEFAULT_HTTP_SIZE_LIMIT);
    }

    public OIDCResourceRetriever(int connectTimeout, int readTimeout, int sizeLimit, boolean disconnectAfterUse) {
        super(connectTimeout, readTimeout, sizeLimit, disconnectAfterUse);
    }

    public OIDCResourceRetriever(int connectTimeout, int readTimeout, int sizeLimit) {
        super(connectTimeout, readTimeout, sizeLimit);
    }

    public OIDCResourceRetriever(int connectTimeout, int readTimeout) {
        super(connectTimeout, readTimeout);
    }

    @Override
    public Resource retrieveResource(URL url) throws IOException {
        logger.debug("attempting to get resource {}", url);
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

    public URL getProxyUrl() {
        return proxyUrl;
    }

    // TODO needed?
    public void setProxyUrl(URL proxyUrl) {
        this.proxyUrl = proxyUrl;
    }

    public boolean isUsePlainTextForHttps() {
        return usePlainTextForHttps;
    }

    // TODO needed?
    public void setUsePlainTextForHttps(boolean usePlainTextForHttps) {
        this.usePlainTextForHttps = usePlainTextForHttps;
    }

    protected URL urlWithPlainTextForHttps(URL url) throws MalformedURLException, URISyntaxException {
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
        if (proxyUrl == null) {
            return null;
        }
        return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyUrl.getHost(), proxyUrl.getPort()));
    }

    private HttpURLConnection openConnection(URL url) throws IOException, URISyntaxException {
        Proxy proxy = getProxy();
        URL urlToOpen = isUsePlainTextForHttps() ? urlWithPlainTextForHttps(url) : url;
        if (proxy == null) {
            return (HttpURLConnection) urlToOpen.openConnection();
        }
        else {
            return (HttpURLConnection) urlToOpen.openConnection(proxy);
        }
    }
}
