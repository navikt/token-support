package no.nav.security.token.support.core.configuration;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import javax.validation.constraints.NotNull;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Getter
@Setter
@ToString
@NoArgsConstructor
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

    @Getter
    @Setter
    @ToString
    public static class Validation {
        private List<String> optionalClaims;

        public Validation(List<String> optionalClaims) {
            this.optionalClaims = Optional.ofNullable(optionalClaims).orElse(Collections.emptyList());
        }

        public Boolean isConfigured() {
            return !optionalClaims.isEmpty();
        }
    }

    @Getter
    @Setter
    @ToString
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
    }
}
