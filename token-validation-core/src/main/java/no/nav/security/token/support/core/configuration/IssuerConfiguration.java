package no.nav.security.token.support.core.configuration;

import com.nimbusds.jose.util.ResourceRetriever;
import no.nav.security.token.support.core.validation.JwtTokenValidator;

import java.net.URL;
import java.util.List;

/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */

public class IssuerConfiguration {

    private String name;
    private ProviderConfiguration metaData;
    private final List<String> acceptedAudience;
    private String cookieName;
    private JwtTokenValidator tokenValidator;
    private ResourceRetriever resourceRetriever;

    public IssuerConfiguration(String shortName, IssuerProperties issuerProperties,
                               ResourceRetriever resourceRetriever) {
        this(shortName,
            issuerProperties.getDiscoveryUrl(),
            issuerProperties.getAcceptedAudience(),
            resourceRetriever);
        this.cookieName = issuerProperties.getCookieName();
    }

    public IssuerConfiguration(String name, URL discoveryUrl, List<String> acceptedAudience,
                               ResourceRetriever resourceRetriever) {
        this(name, new ProviderConfiguration(resourceRetriever, discoveryUrl), acceptedAudience, resourceRetriever);
    }

    public IssuerConfiguration(String name, ProviderConfiguration metaData, List<String> acceptedAudience,
                               ResourceRetriever resourceRetriever) {
        this.name = name;
        this.metaData = metaData;
        this.acceptedAudience = acceptedAudience;
        this.resourceRetriever = resourceRetriever;
        this.tokenValidator = new JwtTokenValidator(metaData.getIssuer(), acceptedAudience,
            metaData.getJwkSetUri(), resourceRetriever);
    }

    public String getName() {
        return name;
    }

    public List<String> getAcceptedAudience() {
        return acceptedAudience;
    }

    // TODO needed?
    public void setTokenValidator(JwtTokenValidator tokenValidator) {
        this.tokenValidator = tokenValidator;
    }

    public JwtTokenValidator getTokenValidator() {
        return tokenValidator;
    }

    public String getCookieName() {
        return cookieName;
    }

    // TODO needed?
    public void setCookieName(String cookieName) {
        this.cookieName = cookieName;
    }

    public ProviderConfiguration getMetaData() {
        return metaData;
    }

    // TODO needed?
    public void setMetaData(ProviderConfiguration metaData) {
        this.metaData = metaData;
    }

    // TODO needed?
    public void setName(String name) {
        this.name = name;
    }

    public ResourceRetriever getResourceRetriever() {
        if (resourceRetriever == null) {
            resourceRetriever = new ProxyAwareResourceRetriever();
        }
        return resourceRetriever;
    }

    // TODO needed?
    public void setResourceRetriever(ResourceRetriever resourceRetriever) {
        this.resourceRetriever = resourceRetriever;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [name=" + name + ", metaData=" + metaData + ", acceptedAudience="
            + acceptedAudience + ", cookieName=" + cookieName + ", tokenValidator=" + tokenValidator
            + ", resourceRetriever=" + resourceRetriever + "]";
    }
}
