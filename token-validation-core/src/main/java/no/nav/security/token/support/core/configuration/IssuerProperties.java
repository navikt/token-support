package no.nav.security.token.support.core.configuration;

import jakarta.validation.constraints.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER;

public class IssuerProperties {
    private static final Logger LOG = LoggerFactory.getLogger(IssuerProperties.class);

    @NotNull
    private URL discoveryUrl;
    private List<String> acceptedAudience;
    private String cookieName;
    private String headerName;
    private URL proxyUrl;
    private boolean usePlaintextForHttps = false;
    private Validation validation = Validation.EMPTY;
    private JwksCache jwksCache = JwksCache.EMPTY;

    public IssuerProperties(URL discoveryUrl) {
        this(discoveryUrl, List.of());
    }

    public IssuerProperties(URL discoveryUrl, List<String> acceptedAudience) {
        this(discoveryUrl,acceptedAudience,null);
    }

    public IssuerProperties(URL discoveryUrl, List<String> acceptedAudience, String cookieName) {
        this(discoveryUrl, acceptedAudience,cookieName,null);
    }

    public IssuerProperties(URL discoveryUrl, List<String> acceptedAudience, String cookieName, String headerName) {
        this(discoveryUrl, acceptedAudience,cookieName,headerName,Validation.EMPTY,JwksCache.EMPTY);
    }

    public IssuerProperties(URL discoveryUrl, Validation validation) {
        this(discoveryUrl,validation,new JwksCache(null, null));
    }

    public IssuerProperties(URL discoveryUrl, JwksCache jwksCache) {
        this(discoveryUrl, List.of(),null,null,Validation.EMPTY,jwksCache);
    }

    public IssuerProperties(URL discoveryUrl, Validation validation, JwksCache jwksCache) {
        this(discoveryUrl, List.of(),null,null,validation,jwksCache);
    }

    public IssuerProperties(URL discoveryUrl, List<String> acceptedAudience, String cookieName, String headerName, Validation validation, JwksCache jwksCache) {
        this.discoveryUrl = Objects.requireNonNull(discoveryUrl, "Discovery URL must be set");
        this.acceptedAudience = Optional.ofNullable(acceptedAudience).orElse(List.of());
        this.cookieName = cookieName(cookieName);
        this.headerName = headerName;
        this.validation = validation;
        this.jwksCache = jwksCache;
    }

    private
    String cookieName(String cookieName) {
        if (cookieName != null) LOG.warn("Cookie-support will be discontinued in future versions, please consider changing yur configuration now");
        return cookieName;
    }

    /**
     *
     */
    @Deprecated(since = "3.1.2",forRemoval = true)
    public IssuerProperties() {
    }

    public @NotNull URL getDiscoveryUrl() {
        return discoveryUrl;
    }

    public List<String> getAcceptedAudience() {
        return acceptedAudience;
    }

    public String getCookieName() {
        return cookieName;
    }

    public String getHeaderName() {
        if (headerName != null && !headerName.isEmpty()) {
            return headerName;
        } else {
            return AUTHORIZATION_HEADER;
        }
    }

    public URL getProxyUrl() {
        return proxyUrl;
    }

    public boolean isUsePlaintextForHttps() {
        return usePlaintextForHttps;
    }

    public Validation getValidation() {
        return validation;
    }

    public JwksCache getJwksCache() {
        return jwksCache;
    }

    @Deprecated(since = "3.1.2",forRemoval = true)
    public void setDiscoveryUrl(@NotNull URL discoveryUrl) {
        this.discoveryUrl = discoveryUrl;
    }

    @Deprecated(since = "3.1.2",forRemoval = true)
    public void setAcceptedAudience(List<String> acceptedAudience) {
        this.acceptedAudience = acceptedAudience;
    }

    @Deprecated(since = "3.1.2",forRemoval = true)
    public void setCookieName(String cookieName) {
        this.cookieName = cookieName;
    }

    @Deprecated(since = "3.1.2",forRemoval = true)
    public void setHeaderName(String headerName) {
        this.headerName = headerName;
    }

    @Deprecated(since = "3.1.2",forRemoval = true)
    public void setProxyUrl(URL proxyUrl) {
        this.proxyUrl = proxyUrl;
    }

    public void setUsePlaintextForHttps(boolean usePlaintextForHttps) {
        this.usePlaintextForHttps = usePlaintextForHttps;
    }

    @Deprecated(since = "3.1.2",forRemoval = true)
    public void setValidation(Validation validation) {
        this.validation = validation;
    }

    @Deprecated(since = "3.1.2",forRemoval = true)
    public void setJwksCache(JwksCache jwksCache) {
        this.jwksCache = jwksCache;
    }

    @Override
    public String toString() {
        return "IssuerProperties(discoveryUrl=" + this.getDiscoveryUrl() + ", acceptedAudience=" + this.getAcceptedAudience() + ", cookieName=" + this.getCookieName() + ", headerName=" + this.getHeaderName() + ", proxyUrl=" + this.getProxyUrl() + ", usePlaintextForHttps=" + this.isUsePlaintextForHttps() + ", validation=" + this.getValidation() + ", jwksCache=" + this.getJwksCache() + ")";
    }

    public static class Validation {

        public static Validation EMPTY = new Validation(List.of());
        private List<String> optionalClaims;

        public Validation(List<String> optionalClaims) {
            this.optionalClaims = Optional.ofNullable(optionalClaims).orElse(List.of());
        }

        public boolean isConfigured() {
            return !optionalClaims.isEmpty();
        }

        public List<String> getOptionalClaims() {
            return this.optionalClaims;
        }

        public void setOptionalClaims(List<String> optionalClaims) {
            this.optionalClaims = optionalClaims;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Validation that = (Validation) o;
            return optionalClaims.equals(that.optionalClaims);
        }

        @Override
        public int hashCode() {
            return Objects.hash(optionalClaims);
        }

        @Override
        public String toString() {
            return "IssuerProperties.Validation(optionalClaims=" + this.getOptionalClaims() + ")";
        }
    }

    public static class JwksCache {

        public static final JwksCache EMPTY = new JwksCache(null, null);
        private Long lifespan;
        private Long refreshTime;

        public JwksCache(Long lifespan, Long refreshTime) {
            this.lifespan = lifespan;
            this.refreshTime = refreshTime;
        }

        public Boolean isConfigured() {
            return lifespan != null && refreshTime != null;
        }

        public Long getLifespan() {
            return this.lifespan;
        }

        public Long getLifespanMillis() {
            return TimeUnit.MINUTES.toMillis(this.lifespan);
        }

        public Long getRefreshTime() {
            return this.refreshTime;
        }

        public Long getRefreshTimeMillis() {
            return TimeUnit.MINUTES.toMillis(this.refreshTime);
        }

        public void setLifespan(Long lifespan) {
            this.lifespan = lifespan;
        }

        public void setRefreshTime(Long refreshTime) {
            this.refreshTime = refreshTime;
        }


        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            var jwksCache = (JwksCache) o;
            return lifespan.equals(jwksCache.lifespan) && refreshTime.equals(jwksCache.refreshTime);
        }

        @Override
        public int hashCode() {
            return Objects.hash(lifespan, refreshTime);
        }

        @Override
        public String toString() {
            return getClass().getSimpleName() + " [lifespan=" + lifespan + ",refreshTime=" + refreshTime + "]";
        }
    }
}
