package no.nav.security.token.support.core.configuration;

import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import no.nav.security.token.support.core.exceptions.MetaDataNotAvailableException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;

public class IssuerMetadata {

    private static final Logger log = LoggerFactory.getLogger(IssuerMetadata.class);
    private String issuer;
    private URL jwkSetUri;

    IssuerMetadata(ResourceRetriever resourceRetriever, URL url) {
        providerMetadata(resourceRetriever, url);
    }

    protected void providerMetadata(ResourceRetriever resourceRetriever, URL url) {
        try {
            AuthorizationServerMetadata authorizationServerMetadata = AuthorizationServerMetadata.parse(resourceRetriever.retrieveResource(url).getContent());
            log.info("Authorization Metadata issuer: " + authorizationServerMetadata.getIssuer().getValue());
            this.issuer = authorizationServerMetadata.getIssuer().getValue();
            this.jwkSetUri = authorizationServerMetadata.getJWKSetURI().toURL();
        } catch (ParseException | IOException e) {
            throw new MetaDataNotAvailableException(url, e);
        }
    }

    public String getIssuer() {
        return issuer;
    }

    public URL getJwkSetUri() {
        return jwkSetUri;
    }
}
