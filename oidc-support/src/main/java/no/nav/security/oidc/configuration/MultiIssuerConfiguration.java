package no.nav.security.oidc.configuration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.nimbusds.jose.util.ResourceRetriever;

public class MultiIssuerConfiguration {

    private final List<String> issuerShortNames = new ArrayList<>();
    private ResourceRetriever resourceRetriever;
    private final Map<String, IssuerConfiguration> issuers = new HashMap<>();

    private Map<String, IssuerProperties> issuerPropertiesMap;

    public MultiIssuerConfiguration(Map<String, IssuerProperties> issuerPropertiesMap) {
        this(issuerPropertiesMap, null);
    }

    public MultiIssuerConfiguration(Map<String, IssuerProperties> issuerPropertiesMap,
            ResourceRetriever resourceRetriever) {
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
        if (resourceRetriever == null) {
            resourceRetriever = createDefaultResourceRetriever();
        }
        return resourceRetriever;
    }

    // TODO needed?
    public void setResourceRetriever(ResourceRetriever resourceRetriever) {
        this.resourceRetriever = resourceRetriever;
    }

    protected void loadIssuerConfigurations() {

        for (Entry<String, IssuerProperties> entry : issuerPropertiesMap.entrySet()) {
            String shortName = entry.getKey();
            issuerShortNames.add(shortName);
            IssuerConfiguration config = createIssuerConfiguration(shortName, entry.getValue());
            issuers.put(shortName, config);
            issuers.put(config.getMetaData().getIssuer().toString(), config);
        }
    }

    private IssuerConfiguration createIssuerConfiguration(String shortName, IssuerProperties issuerProperties) {
        if (issuerProperties.getProxyUrl() != null) {
            OIDCResourceRetriever resourceRetrieverWithProxy = new OIDCResourceRetriever();
            resourceRetrieverWithProxy.setProxyUrl(issuerProperties.getProxyUrl());
            resourceRetrieverWithProxy.setUsePlainTextForHttps(issuerProperties.isUsePlaintextForHttps());
            return new IssuerConfiguration(shortName, issuerProperties, resourceRetrieverWithProxy);
        }
        return new IssuerConfiguration(shortName, issuerProperties, getResourceRetriever());
    }

    protected ResourceRetriever createDefaultResourceRetriever() {
        return new OIDCResourceRetriever();
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [issuerShortNames=" + issuerShortNames + ", resourceRetriever="
                + resourceRetriever + ", issuers=" + issuers + ", issuerPropertiesMap=" + issuerPropertiesMap + "]";
    }
}
