package no.nav.security.token.support.core.configuration;

import jakarta.validation.constraints.NotNull;

import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static java.util.Objects.requireNonNull;
import static no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER;

public class IssuerProperties {
    @NotNull
    private URL discoveryUrl;
    private List<String> acceptedAudience;
    private String cookieName;
    private String headerName;
    private URL proxyUrl;
    private boolean usePlaintextForHttps = false;
    private Validation validation = new Validation(Collections.emptyList());
    private JwksCache jwksCache = new JwksCache(null, null);

    public IssuerProperties(URL discoveryUrl) {
        this.discoveryUrl = discoveryUrl;
    }

    public IssuerProperties(URL discoveryUrl, List<String> acceptedAudience) {
        this.discoveryUrl = requireNonNull(discoveryUrl);
        this.acceptedAudience = acceptedAudience;
    }

    public IssuerProperties(URL discoveryUrl, List<String> acceptedAudience, String cookieName) {
        this(discoveryUrl, acceptedAudience);
        this.cookieName = cookieName;
    }

    public IssuerProperties(URL discoveryUrl, List<String> acceptedAudience, String cookieName, String headerName) {
        this(discoveryUrl, acceptedAudience);
        this.cookieName = cookieName;
        this.headerName = headerName;
    }

    public IssuerProperties(URL discoveryUrl, Validation validation) {
        this(discoveryUrl);
        this.validation = validation;
    }

    public IssuerProperties(URL discoveryUrl, JwksCache jwksCache) {
        this(discoveryUrl);
        this.jwksCache = jwksCache;
    }

    public IssuerProperties(URL discoveryUrl, Validation validation, JwksCache jwksCache) {
        this(discoveryUrl, validation);
        this.jwksCache = jwksCache;
    }

    public IssuerProperties(URL discoveryUrl, List<String> acceptedAudience, String cookieName, String headerName, Validation validation, JwksCache jwksCache) {
        this(discoveryUrl, acceptedAudience);
        this.cookieName = cookieName;
        this.headerName = headerName;
        this.validation = validation;
        this.jwksCache = jwksCache;
    }

    public IssuerProperties() {
    }

    public @NotNull URL getDiscoveryUrl() {
        return this.discoveryUrl;
    }

    public List<String> getAcceptedAudience() {
        return this.acceptedAudience;
    }

    public String getCookieName() {
        return this.cookieName;
    }

    public String getHeaderName() {
        if (this.headerName != null && !this.headerName.isEmpty()) {
            return this.headerName;
        } else {
            return AUTHORIZATION_HEADER;
        }
    }

    public URL getProxyUrl() {
        return this.proxyUrl;
    }

    public boolean isUsePlaintextForHttps() {
        return this.usePlaintextForHttps;
    }

    public Validation getValidation() {
        return this.validation;
    }

    public JwksCache getJwksCache() {
        return this.jwksCache;
    }

    public void setDiscoveryUrl(@NotNull URL discoveryUrl) {
        this.discoveryUrl = discoveryUrl;
    }

    public void setAcceptedAudience(List<String> acceptedAudience) {
        this.acceptedAudience = acceptedAudience;
    }

    public void setCookieName(String cookieName) {
        this.cookieName = cookieName;
    }

    public void setHeaderName(String headerName) {
        this.headerName = headerName;
    }

    public void setProxyUrl(URL proxyUrl) {
        this.proxyUrl = proxyUrl;
    }

    public void setUsePlaintextForHttps(boolean usePlaintextForHttps) {
        this.usePlaintextForHttps = usePlaintextForHttps;
    }

    public void setValidation(Validation validation) {
        this.validation = validation;
    }

    public void setJwksCache(JwksCache jwksCache) {
        this.jwksCache = jwksCache;
    }

    @Override
    public String toString() {
        return "IssuerProperties(discoveryUrl=" + this.getDiscoveryUrl() + ", acceptedAudience=" + this.getAcceptedAudience() + ", cookieName=" + this.getCookieName() + ", headerName=" + this.getHeaderName() + ", proxyUrl=" + this.getProxyUrl() + ", usePlaintextForHttps=" + this.isUsePlaintextForHttps() + ", validation=" + this.getValidation() + ", jwksCache=" + this.getJwksCache() + ")";
    }

    public static class Validation {
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
        private Long lifespan;
        private Long refreshTime;

        public JwksCache(Long lifespan, Long refreshTime) {
            this.lifespan = Optional.ofNullable(lifespan).orElse(null);
            this.refreshTime = Optional.ofNullable(refreshTime).orElse(null);
        }

        public Boolean isConfigured() {
            return lifespan != null && refreshTime != null;
        }

        public Long getLifespan() {
            return this.lifespan;
        }

        public Long getRefreshTime() {
            return this.refreshTime;
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
