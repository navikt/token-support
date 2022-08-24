package no.nav.security.token.support.core.configuration;

import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import no.nav.security.token.support.core.exceptions.MetaDataNotAvailableException;
import no.nav.security.token.support.core.validation.JwtTokenValidator;

import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.Optional;

import static no.nav.security.token.support.core.validation.JwtTokenValidatorFactory.tokenValidator;

public class IssuerConfiguration {

    private final String name;
    private final AuthorizationServerMetadata metadata;
    private final List<String> acceptedAudience;
    private final String cookieName;
    private final String headerName;
    private final JwtTokenValidator tokenValidator;
    private final ResourceRetriever resourceRetriever;

    public IssuerConfiguration(String name, IssuerProperties issuerProperties, ResourceRetriever retriever) {
        this.name = name;
        this.resourceRetriever = Optional.ofNullable(retriever).orElseGet(ProxyAwareResourceRetriever::new);
        this.metadata = getProviderMetadata(resourceRetriever, issuerProperties.getDiscoveryUrl());
        this.acceptedAudience = issuerProperties.getAcceptedAudience();
        this.cookieName = issuerProperties.getCookieName();
        this.headerName = issuerProperties.getHeaderName();
        this.tokenValidator = tokenValidator(issuerProperties, metadata, resourceRetriever);
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

    public String getHeaderName() {
        return headerName;
    }

    public AuthorizationServerMetadata getMetaData() {
        return metadata;
    }

    public ResourceRetriever getResourceRetriever() {
        return resourceRetriever;
    }

    protected static AuthorizationServerMetadata getProviderMetadata(ResourceRetriever resourceRetriever, URL url) {
        try {
            return AuthorizationServerMetadata.parse(resourceRetriever.retrieveResource(url).getContent());
        } catch (ParseException | IOException e) {
            throw new MetaDataNotAvailableException("Make sure you are not using proxying in GCP", url, e);
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [name=" + name + ", metaData=" + metadata + ", acceptedAudience="
            + acceptedAudience + ", cookieName=" + cookieName + ", headerName=" + headerName + ", tokenValidator=" + tokenValidator
            + ", resourceRetriever=" + resourceRetriever + "]";
    }
}
