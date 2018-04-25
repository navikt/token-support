package no.nav.security.oidc.configuration;


import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.util.ResourceRetriever;

public class MultiIssuerConfiguraton {
	
	private List<String> issuerShortNames;
	private ResourceRetriever resourceRetriever;
	private Map<String, IssuerConfiguration> issuers = new HashMap<String, IssuerConfiguration>();
		
	private List<IssuerProperties> issuerPropertiesList;
	
	public MultiIssuerConfiguraton(List<IssuerProperties> issuerPropertiesList){
		this(issuerPropertiesList, null);
	}
	
	public MultiIssuerConfiguraton(List<IssuerProperties> issuerPropertiesList, ResourceRetriever resourceRetriever){
		this.issuerPropertiesList = issuerPropertiesList;
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
				+ resourceRetriever + ", issuers=" + issuers + ", issuerPropertiesList=" + issuerPropertiesList + "]";
	}
	
	protected void loadIssuerConfigurations(){
		for (IssuerProperties issuerProperties : issuerPropertiesList) {
			this.issuerShortNames.add(issuerProperties.getShortName());
			IssuerConfiguration config = new IssuerConfiguration(issuerProperties, getResourceRetriever());
			issuers.put(issuerProperties.getShortName(), config);
			issuers.put(config.getMetaData().getIssuer().toString(), config);
		}
	}
	
	protected ResourceRetriever createDefaultResourceRetriever(){
		return new OIDCResourceRetriever();
	}
}
