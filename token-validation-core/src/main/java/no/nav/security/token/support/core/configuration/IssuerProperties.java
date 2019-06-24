package no.nav.security.token.support.core.configuration;

import java.net.URL;
import java.util.List;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

public class IssuerProperties {
    @NotNull
    private URL discoveryUrl;
    @NotEmpty
    private List<String> acceptedAudience;
    private String cookieName;
    private URL proxyUrl;
    private boolean usePlaintextForHttps = false;

    // TODO needed?
    public IssuerProperties() {
    }

    public IssuerProperties(URL discoveryUrl, List<String> acceptedAudience) {
        this.discoveryUrl = discoveryUrl;
        this.acceptedAudience = acceptedAudience;
    }

    public IssuerProperties(URL discoveryUrl, List<String> acceptedAudience, String cookieName) {
        this(discoveryUrl, acceptedAudience);
        this.cookieName = cookieName;
    }

    public URL getDiscoveryUrl() {
        return discoveryUrl;
    }

    // TODO needed?
    public void setDiscoveryUrl(URL discoveryUrl) {
        this.discoveryUrl = discoveryUrl;
    }

    public String getCookieName() {
        return cookieName != null ? cookieName.trim() : cookieName;
    }

    // TODO needed?
    public void setCookieName(String cookieName) {
        this.cookieName = cookieName;
    }

    public List<String> getAcceptedAudience() {
        return acceptedAudience;
    }

    // TODO needed?
    public void setAcceptedAudience(List<String> acceptedAudience) {
        this.acceptedAudience = acceptedAudience;
    }

    public URL getProxyUrl() {
        return proxyUrl;
    }

    // TODO needed?
    public void setProxyUrl(URL proxyUrl) {
        this.proxyUrl = proxyUrl;
    }

    public boolean isUsePlaintextForHttps() {
        return usePlaintextForHttps;
    }

    public void setUsePlaintextForHttps(boolean usePlaintextForHttps) {
        this.usePlaintextForHttps = usePlaintextForHttps;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "{" +
                "discoveryUrl=" + discoveryUrl +
                ", acceptedAudience=" + acceptedAudience +
                ", cookieName='" + cookieName + '\'' +
                ", proxyUrl=" + proxyUrl +
                '}';
    }
}
