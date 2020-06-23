package no.nav.security.token.support.core.configuration;

import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import no.nav.security.token.support.core.exceptions.MetaDataNotAvailableException;
import no.nav.security.token.support.core.validation.DefaultJwtTokenValidator;

import java.io.IOException;
import java.net.MalformedURLException;
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
    private AuthorizationServerMetadata metaData;
    private final List<String> acceptedAudience;
    private String cookieName;
    private DefaultJwtTokenValidator tokenValidator;
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
        this(name, getProviderMetadata(resourceRetriever, discoveryUrl), acceptedAudience, resourceRetriever);
    }

    public IssuerConfiguration(String name, AuthorizationServerMetadata metaData, List<String> acceptedAudience,
                               ResourceRetriever resourceRetriever) {
        this.name = name;
        this.metaData = metaData;
        this.acceptedAudience = acceptedAudience;
        this.resourceRetriever = resourceRetriever;
        this.tokenValidator = new DefaultJwtTokenValidator(metaData.getIssuer().getValue(), acceptedAudience, getJwksUrl(metaData), resourceRetriever);
    }

    public String getName() {
        return name;
    }

    public List<String> getAcceptedAudience() {
        return acceptedAudience;
    }

    // TODO needed?
    public void setTokenValidator(DefaultJwtTokenValidator tokenValidator) {
        this.tokenValidator = tokenValidator;
    }

    public DefaultJwtTokenValidator getTokenValidator() {
        return tokenValidator;
    }

    public String getCookieName() {
        return cookieName;
    }

    // TODO needed?
    public void setCookieName(String cookieName) {
        this.cookieName = cookieName;
    }

    public AuthorizationServerMetadata getMetaData() {
        return metaData;
    }

    // TODO needed?
    public void setMetaData(AuthorizationServerMetadata metaData) {
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

    protected static URL getJwksUrl(AuthorizationServerMetadata metaData) {
        try {
            return metaData.getJWKSetURI().toURL();
        } catch (MalformedURLException e) {
            throw new MetaDataNotAvailableException(e);
        }
    }

    protected static AuthorizationServerMetadata getProviderMetadata(ResourceRetriever resourceRetriever, URL url) {
        if (url == null) {
            throw new MetaDataNotAvailableException("discoveryUrl cannot be null, check your configuration.");
        }
        try {
            return AuthorizationServerMetadata.parse(resourceRetriever.retrieveResource(url).getContent());
        } catch (ParseException | IOException e) {
            throw new MetaDataNotAvailableException(url, e);
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [name=" + name + ", metaData=" + metaData + ", acceptedAudience="
            + acceptedAudience + ", cookieName=" + cookieName + ", tokenValidator=" + tokenValidator
            + ", resourceRetriever=" + resourceRetriever + "]";
    }
}
