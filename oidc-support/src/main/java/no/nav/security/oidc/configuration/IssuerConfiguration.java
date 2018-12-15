package no.nav.security.oidc.configuration;

import java.io.IOException;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import no.nav.security.oidc.exceptions.MetaDataNotAvailableException;
import no.nav.security.oidc.validation.OIDCTokenValidator;

public class IssuerConfiguration {

    private String name;
    private OIDCProviderMetadata metaData;
    private List<String> acceptedAudience;
    private String cookieName;
    private OIDCTokenValidator tokenValidator;
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

    public IssuerConfiguration(String name, OIDCProviderMetadata metaData, List<String> acceptedAudience,
            ResourceRetriever resourceRetriever) {
        this.name = name;
        this.metaData = metaData;
        this.acceptedAudience = acceptedAudience;
        this.resourceRetriever = resourceRetriever;
        this.tokenValidator = new OIDCTokenValidator(metaData.getIssuer().toString(), acceptedAudience,
                getJwksUrl(metaData), resourceRetriever);
    }

    public String getName() {
        return name;
    }

    public List<String> getAcceptedAudience() {
        return acceptedAudience;
    }

    // TODO needed?
    public void setTokenValidator(OIDCTokenValidator tokenValidator) {
        this.tokenValidator = tokenValidator;
    }

    public OIDCTokenValidator getTokenValidator() {
        return tokenValidator;
    }

    public String getCookieName() {
        return cookieName;
    }

    // TODO needed?
    public void setCookieName(String cookieName) {
        this.cookieName = cookieName;
    }

    public OIDCProviderMetadata getMetaData() {
        return metaData;
    }

    // TODO needed?
    public void setMetaData(OIDCProviderMetadata metaData) {
        this.metaData = metaData;
    }

    // TODO needed?
    public void setName(String name) {
        this.name = name;
    }

    public ResourceRetriever getResourceRetriever() {
        if (resourceRetriever == null) {
            resourceRetriever = new OIDCResourceRetriever();
        }
        return resourceRetriever;
    }

    // TODO needed?
    public void setResourceRetriever(ResourceRetriever resourceRetriever) {
        this.resourceRetriever = resourceRetriever;
    }

    protected static URL getJwksUrl(OIDCProviderMetadata metaData) {
        try {
            return metaData.getJWKSetURI().toURL();
        } catch (MalformedURLException e) {
            throw new MetaDataNotAvailableException(e);
        }
    }

    protected static OIDCProviderMetadata getProviderMetadata(ResourceRetriever resourceRetriever, URL url) {
        if (url == null) {
            throw new MetaDataNotAvailableException("discoveryUrl cannot be null, check your configuration.");
        }
        try {
            return OIDCProviderMetadata.parse(resourceRetriever.retrieveResource(url).getContent());
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
