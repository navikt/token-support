package no.nav.security.oidc.configuration;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import com.nimbusds.jose.util.ResourceRetriever;
import no.nav.security.oidc.exceptions.MissingPropertyException;

public class MultiIssuerPropertiesConfiguration extends MultiIssuerConfiguraton {
	
	public MultiIssuerPropertiesConfiguration(OIDCProperties properties) {		
		super(createIssuerPropertiesList(properties));
	}
	
	public MultiIssuerPropertiesConfiguration(OIDCProperties properties, ResourceRetriever resourceRetriever) {
		super(createIssuerPropertiesList(properties), resourceRetriever);
	}
	
	private static List<IssuerProperties> createIssuerPropertiesList(OIDCProperties properties){
		List<IssuerProperties> issuerPropertiesList = new ArrayList<>();	
		String[] issuerNames = getNotBlank(OIDCProperties.ISSUERS, properties).split(",");
		
		for (String issuerName : issuerNames) {
			issuerName = issuerName.trim();
			URL url = getDiscoveryUrlByIssuerName(OIDCProperties.URI, properties, issuerName);
			String acceptedAudience = getPropertyByIssuerName(OIDCProperties.ACCEPTEDAUDIENCE, properties, issuerName);
			String cookieName = getPropertyByIssuerName(OIDCProperties.COOKIE_NAME, properties, issuerName);
			issuerPropertiesList.add(new IssuerProperties(issuerName, url, cookieName, acceptedAudience));
		}
		return issuerPropertiesList;
	}
	
	private static URL getDiscoveryUrlByIssuerName(String key, OIDCProperties properties, String issuerName) {
		try {
			String url = getPropertyByIssuerName(key, properties, issuerName);
			return URI.create(url.trim()).toURL();
		} catch (MalformedURLException e){
			throw new IllegalArgumentException(e);
		}		
	}
	
	private static String getPropertyByIssuerName(String key, OIDCProperties properties, String issuerName){
		return getNotBlank(String.format(key, issuerName), properties);
	}
	
	private static String getNotBlank(String key, OIDCProperties properties){
		String value = properties.get(key);
		if(StringUtils.isBlank(value)){
			throw new MissingPropertyException(String.format("missing required property with key %s", key));
		}
		return value;
	}
}
