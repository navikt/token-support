package no.nav.security.oidc.configuration;


import java.io.IOException;
import java.net.URL;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import no.nav.security.oidc.exceptions.MetaDataNotAvailableException;
import no.nav.security.oidc.exceptions.MissingPropertyException;

public class OIDCValidationConfiguraton {
	
	private OIDCProperties properties;
	private Map<String, IssuerValidationConfiguration> issuers = new HashMap<String, IssuerValidationConfiguration>();
	private List<String> issuerNames;
	private ResourceRetriever resourceRetriever;
	
	public OIDCValidationConfiguraton(OIDCProperties props) {
		this.properties = props;
		this.issuerNames = new ArrayList<>();
		load();
	}
	
	public OIDCValidationConfiguraton(OIDCProperties props, ResourceRetriever resourceRetriever) {
		this.properties = props;
		this.issuerNames = new ArrayList<>();
		this.resourceRetriever = resourceRetriever;
		load();
	}

	public IssuerValidationConfiguration getIssuer(String name) {
		return issuers.get(name);
	}

	private void load() {
		String[] issuerNames = getNotBlank(OIDCProperties.ISSUERS).split(",");
		for (String issuerName : issuerNames) {
			issuerName = issuerName.trim();
			String uri = getNotBlank(String.format(OIDCProperties.URI, issuerName));
			if (uri.trim().length() > 0) {
				this.issuerNames.add(issuerName);
				try {
					OIDCProviderMetadata metadata = getProviderMetadata(uri);
				
					IssuerValidationConfiguration config = new IssuerValidationConfiguration(issuerName, metadata,
							getNotBlank(String.format(OIDCProperties.ACCEPTEDAUDIENCE, issuerName)), 
							getResourceRetriever());
					
					config.setCookieName(properties.get(String.format(OIDCProperties.COOKIE_NAME, issuerName)));
					
					issuers.put(issuerName, config);
					issuers.put(metadata.getIssuer().toString(), config);
				} catch (Exception e) {
					throw new MetaDataNotAvailableException(e);
				}
			}
		}
	}
	
	protected OIDCProviderMetadata getProviderMetadata(String uri){	
		try {
			return OIDCProviderMetadata.parse(getResourceRetriever().retrieveResource(
			                new URL(uri)).getContent());
		} catch (ParseException | IOException e) {
			throw new MetaDataNotAvailableException(e);
		}
	}
	
	public List<String>getIssuerNames() {
		return this.issuerNames;
	}
	
	public ResourceRetriever getResourceRetriever() {
		if(resourceRetriever == null){
			resourceRetriever = new OIDCResourceRetriever();
		}
		return resourceRetriever;
	}

	public void setResourceRetriever(ResourceRetriever resourceRetriever) {
		this.resourceRetriever = resourceRetriever;
	}

	private String getNotBlank(String key){
		String value = properties.get(key);
		if(StringUtils.isBlank(value)){
			throw new MissingPropertyException(String.format("missing required property with key %s", key));
		}
		return value;
	}
}
