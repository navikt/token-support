package no.nav.security.oidc.configuration;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.nimbusds.jose.util.ResourceRetriever;

public class MultiIssuerConfiguration {
	
	private List<String> issuerShortNames = new ArrayList<>();
	private ResourceRetriever resourceRetriever;
	private Map<String, IssuerConfiguration> issuers = new HashMap<String, IssuerConfiguration>();
		
	private Map<String, IssuerProperties> issuerPropertiesMap;
	
	public MultiIssuerConfiguration(Map<String, IssuerProperties> issuerPropertiesMap){
		this(issuerPropertiesMap, null);
	}
	
	public MultiIssuerConfiguration(Map<String, IssuerProperties> issuerPropertiesMap, ResourceRetriever resourceRetriever){
		this.issuerPropertiesMap = issuerPropertiesMap;
		this.resourceRetriever = resourceRetriever;
		loadIssuerConfigurations();
	}

	public IssuerConfiguration getIssuer(String name) {
		return issuers.get(name);
	}
	
	public List<String> getIssuerShortNames() {
		return this.issuerShortNames;
	}
	
	public ResourceRetriever getResourceRetriever() {
		if(resourceRetriever == null){
			resourceRetriever = createDefaultResourceRetriever();
		}
		return resourceRetriever;
	}
	
	public void setResourceRetriever(ResourceRetriever resourceRetriever) {
		this.resourceRetriever = resourceRetriever;
	}
	
	protected void loadIssuerConfigurations(){
		
		for (Entry<String, IssuerProperties> entry : issuerPropertiesMap.entrySet()) {
			String shortName = entry.getKey();
			this.issuerShortNames.add(shortName);
			IssuerConfiguration config = createIssuerConfiguration(shortName, entry.getValue());
			this.issuers.put(shortName, config);
			this.issuers.put(config.getMetaData().getIssuer().toString(), config);
		}
	}

	private IssuerConfiguration createIssuerConfiguration(String shortName, IssuerProperties issuerProperties){
		if(issuerProperties.getProxyUrl() != null){
			OIDCResourceRetriever resourceRetrieverWithProxy = new OIDCResourceRetriever();
			resourceRetrieverWithProxy.setProxyUrl(issuerProperties.getProxyUrl());
			resourceRetrieverWithProxy.setUsePlainTextForHttps(issuerProperties.isUsePlaintextForHttps());
			return new IssuerConfiguration(shortName, issuerProperties, resourceRetrieverWithProxy);
		} else {
			return new IssuerConfiguration(shortName, issuerProperties, getResourceRetriever());
		}
	}

	protected ResourceRetriever createDefaultResourceRetriever(){
		return new OIDCResourceRetriever();
	}

	@Override
	public String toString() {
		return "MultiIssuerConfiguration [issuerShortNames=" + issuerShortNames + ", resourceRetriever="
				+ resourceRetriever + ", issuers=" + issuers + ", issuerPropertiesMap=" + issuerPropertiesMap + "]";
	}
}
