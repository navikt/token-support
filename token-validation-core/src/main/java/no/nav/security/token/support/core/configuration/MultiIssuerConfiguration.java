package no.nav.security.token.support.core.configuration;

import com.nimbusds.jose.util.ResourceRetriever;

import java.util.*;
import java.util.Map.Entry;

public class MultiIssuerConfiguration {

    private final List<String> issuerShortNames = new ArrayList<>();
    private ResourceRetriever resourceRetriever;

    private final Map<String, IssuerConfiguration> issuers = new HashMap<>();

    private final Map<String, IssuerProperties> issuerPropertiesMap;

    public MultiIssuerConfiguration(Map<String, IssuerProperties> issuerPropertiesMap) {
        this(issuerPropertiesMap, null);
    }

    public MultiIssuerConfiguration(Map<String, IssuerProperties> issuerPropertiesMap,
                                    ResourceRetriever resourceRetriever) {
        this.issuerPropertiesMap = issuerPropertiesMap;
        this.resourceRetriever = resourceRetriever;
        loadIssuerConfigurations();
    }

    public Map<String, IssuerConfiguration> getIssuers() {
        return issuers;
    }

    public Optional<IssuerConfiguration> getIssuer(String name) {
        return Optional.ofNullable(issuers.get(name));
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

    private void loadIssuerConfigurations() {

        for (Entry<String, IssuerProperties> entry : issuerPropertiesMap.entrySet()) {
            String shortName = entry.getKey();
            issuerShortNames.add(shortName);
            IssuerConfiguration config = createIssuerConfiguration(shortName, entry.getValue());
            issuers.put(shortName, config);
            issuers.put(config.getMetaData().getIssuer().toString(), config);
        }
    }

    private IssuerConfiguration createIssuerConfiguration(String shortName, IssuerProperties issuerProperties) {
        if (issuerProperties.isUsePlaintextForHttps() || issuerProperties.getProxyUrl() != null){
            ProxyAwareResourceRetriever resourceRetrieverWithProxy =
                new ProxyAwareResourceRetriever(issuerProperties.getProxyUrl(), issuerProperties.isUsePlaintextForHttps());

            return new IssuerConfiguration(shortName, issuerProperties, resourceRetrieverWithProxy);
        }
        return new IssuerConfiguration(shortName, issuerProperties, getResourceRetriever());
    }

    protected ResourceRetriever createDefaultResourceRetriever() {
        return new ProxyAwareResourceRetriever();
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [issuerShortNames=" + issuerShortNames + ", resourceRetriever="
            + resourceRetriever + ", issuers=" + issuers + ", issuerPropertiesMap=" + issuerPropertiesMap + "]";
    }
}
