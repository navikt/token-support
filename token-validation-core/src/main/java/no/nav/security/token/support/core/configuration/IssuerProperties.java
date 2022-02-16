package no.nav.security.token.support.core.configuration;

import javax.validation.constraints.NotNull;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public class IssuerProperties {
    @NotNull
    private URL discoveryUrl;
    private List<String> acceptedAudience;
    private String cookieName;
    private URL proxyUrl;
    private boolean usePlaintextForHttps = false;
    private Validation validation = new Validation(Collections.emptyList());
    private JwksCache jwksCache = new JwksCache(null, null);

    public IssuerProperties(URL discoveryUrl) {
        this.discoveryUrl = discoveryUrl;
    }

    public IssuerProperties(URL discoveryUrl, List<String> acceptedAudience) {
        this.discoveryUrl = discoveryUrl;
        this.acceptedAudience = acceptedAudience;
    }

    public IssuerProperties(URL discoveryUrl, List<String> acceptedAudience, String cookieName) {
        this(discoveryUrl, acceptedAudience);
        this.cookieName = cookieName;
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

    public IssuerProperties(URL discoveryUrl, List<String> acceptedAudience, String cookieName, Validation validation, JwksCache jwksCache) {
        this(discoveryUrl, acceptedAudience);
        this.cookieName = cookieName;
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

    public String toString() {
        return "IssuerProperties(discoveryUrl=" + this.getDiscoveryUrl() + ", acceptedAudience=" + this.getAcceptedAudience() + ", cookieName=" + this.getCookieName() + ", proxyUrl=" + this.getProxyUrl() + ", usePlaintextForHttps=" + this.isUsePlaintextForHttps() + ", validation=" + this.getValidation() + ", jwksCache=" + this.getJwksCache() + ")";
    }

    public static class Validation {
        private List<String> optionalClaims;

        public Validation(List<String> optionalClaims) {
            this.optionalClaims = Optional.ofNullable(optionalClaims).orElse(Collections.emptyList());
        }

        public Boolean isConfigured() {
            return !optionalClaims.isEmpty();
        }

        public List<String> getOptionalClaims() {
            return this.optionalClaims;
        }

        public void setOptionalClaims(List<String> optionalClaims) {
            this.optionalClaims = optionalClaims;
        }

        public boolean equals(final Object o) {
            if (o == this) return true;
            if (!(o instanceof Validation)) return false;
            final Validation other = (Validation) o;
            if (!other.canEqual((Object) this)) return false;
            final Object this$optionalClaims = this.getOptionalClaims();
            final Object other$optionalClaims = other.getOptionalClaims();
            if (this$optionalClaims == null ? other$optionalClaims != null : !this$optionalClaims.equals(other$optionalClaims))
                return false;
            return true;
        }

        protected boolean canEqual(final Object other) {
            return other instanceof Validation;
        }

        public int hashCode() {
            final int PRIME = 59;
            int result = 1;
            final Object $optionalClaims = this.getOptionalClaims();
            result = result * PRIME + ($optionalClaims == null ? 43 : $optionalClaims.hashCode());
            return result;
        }

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

        public boolean equals(final Object o) {
            if (o == this) return true;
            if (!(o instanceof JwksCache)) return false;
            final JwksCache other = (JwksCache) o;
            if (!other.canEqual((Object) this)) return false;
            final Object this$lifespan = this.getLifespan();
            final Object other$lifespan = other.getLifespan();
            if (this$lifespan == null ? other$lifespan != null : !this$lifespan.equals(other$lifespan)) return false;
            final Object this$refreshTime = this.getRefreshTime();
            final Object other$refreshTime = other.getRefreshTime();
            if (this$refreshTime == null ? other$refreshTime != null : !this$refreshTime.equals(other$refreshTime))
                return false;
            return true;
        }

        protected boolean canEqual(final Object other) {
            return other instanceof JwksCache;
        }

        public int hashCode() {
            final int PRIME = 59;
            int result = 1;
            final Object $lifespan = this.getLifespan();
            result = result * PRIME + ($lifespan == null ? 43 : $lifespan.hashCode());
            final Object $refreshTime = this.getRefreshTime();
            result = result * PRIME + ($refreshTime == null ? 43 : $refreshTime.hashCode());
            return result;
        }

        public String toString() {
            return "IssuerProperties.JwksCache(lifespan=" + this.getLifespan() + ", refreshTime=" + this.getRefreshTime() + ")";
        }
    }
}
