package no.nav.security.token.support.core.configuration;

import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import no.nav.security.token.support.core.exceptions.MetaDataNotAvailableException;
import no.nav.security.token.support.core.validation.ConfigurableJwtTokenValidator;
import no.nav.security.token.support.core.validation.DefaultJwtTokenValidator;
import no.nav.security.token.support.core.validation.JwtTokenValidator;

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
    private final JwtTokenValidator tokenValidator;
    private ResourceRetriever resourceRetriever;

    public IssuerConfiguration(String name, IssuerProperties issuerProperties, ResourceRetriever resourceRetriever) {
        this.name = name;
        this.resourceRetriever = resourceRetriever;
        this.metaData = getProviderMetadata(resourceRetriever, issuerProperties.getDiscoveryUrl());
        this.acceptedAudience = issuerProperties.getAcceptedAudience();
        this.cookieName = issuerProperties.getCookieName();
        this.tokenValidator = createTokenValidator(issuerProperties);
    }

    public String getName() {
        return name;
    }

    public List<String> getAcceptedAudience() {
        return acceptedAudience;
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

    private JwtTokenValidator createTokenValidator(IssuerProperties issuerProperties) {
        if (issuerProperties.getValidation().isConfigured() ||
            issuerProperties.getJwkSetCache().isConfigured()) {
            return new ConfigurableJwtTokenValidator(
                metaData.getIssuer().getValue(),
                getJwksUrl(metaData),
                resourceRetriever,
                issuerProperties.getValidation().getOptionalClaims(),
                issuerProperties.getJwkSetCache()
            );
        } else {
            return new DefaultJwtTokenValidator(
                metaData.getIssuer().getValue(),
                acceptedAudience,
                getJwksUrl(metaData),
                resourceRetriever
            );
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [name=" + name + ", metaData=" + metaData + ", acceptedAudience="
            + acceptedAudience + ", cookieName=" + cookieName + ", tokenValidator=" + tokenValidator
            + ", resourceRetriever=" + resourceRetriever + "]";
    }
}
