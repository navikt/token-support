package no.nav.security.oidc.configuration;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.nimbusds.jose.util.ResourceRetriever;

public class MultiIssuerConfiguraton {
	
	private List<String> issuerShortNames = new ArrayList<>();
	private ResourceRetriever resourceRetriever;
	private Map<String, IssuerConfiguration> issuers = new HashMap<String, IssuerConfiguration>();
		
	private Map<String, IssuerProperties> issuerPropertiesMap;
	
	public MultiIssuerConfiguraton(Map<String, IssuerProperties> issuerPropertiesMap){
		this(issuerPropertiesMap, null);
	}
	
	public MultiIssuerConfiguraton(Map<String, IssuerProperties> issuerPropertiesMap, ResourceRetriever resourceRetriever){
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
	
	@Override
	public String toString() {
		return "MultiIssuerConfiguraton [issuerShortNames=" + issuerShortNames + ", resourceRetriever="
				+ resourceRetriever + ", issuers=" + issuers + ", issuerPropertiesMap=" + issuerPropertiesMap + "]";
	}
	
	protected void loadIssuerConfigurations(){
		
		for (Entry<String, IssuerProperties> entry : issuerPropertiesMap.entrySet()) {
			String name = entry.getKey();
			this.issuerShortNames.add(name);
			IssuerConfiguration config = new IssuerConfiguration(name, entry.getValue(), getResourceRetriever());
			issuers.put(name, config);
			issuers.put(config.getMetaData().getIssuer().toString(), config);
		}
	}
	
	protected ResourceRetriever createDefaultResourceRetriever(){
		return new OIDCResourceRetriever();
	}
}
