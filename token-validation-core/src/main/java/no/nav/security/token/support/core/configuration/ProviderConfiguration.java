package no.nav.security.token.support.core.configuration;

import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import no.nav.security.token.support.core.exceptions.MetaDataNotAvailableException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;

public class ProviderConfiguration {

    private static final Logger log = LoggerFactory.getLogger(ProviderConfiguration.class);
    private String issuer;
    private URL jwkSetUri;

    ProviderConfiguration(ResourceRetriever resourceRetriever, URL url) {
        providerMetadata(resourceRetriever, url);
    }

    protected static Boolean isOauthServer(URL url) {
        return url.toString().contains("oauth-authorization-server");
    }

    protected void providerMetadata(ResourceRetriever resourceRetriever, URL url) {
        try {
            if (isOauthServer(url)) {
                AuthorizationServerMetadata authorizationServerMetadata = AuthorizationServerMetadata.parse(resourceRetriever.retrieveResource(url).getContent());
                log.info("Authorization Metadata issuer: " + authorizationServerMetadata.getIssuer().getValue());
                this.issuer = authorizationServerMetadata.getIssuer().getValue();
                this.jwkSetUri = authorizationServerMetadata.getJWKSetURI().toURL();
            } else {
                OIDCProviderMetadata oidcMetadata = OIDCProviderMetadata.parse(resourceRetriever.retrieveResource(url).getContent());
                log.info("Authorization Metadata issuer: " + oidcMetadata.getIssuer().getValue());
                this.issuer = oidcMetadata.getIssuer().getValue();
                this.jwkSetUri = oidcMetadata.getJWKSetURI().toURL();
            }
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
