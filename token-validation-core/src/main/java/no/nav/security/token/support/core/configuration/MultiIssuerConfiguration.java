package no.nav.security.token.support.core.configuration;

import com.nimbusds.jose.util.ResourceRetriever;

import java.util.*;

public class MultiIssuerConfiguration {

    private final List<String> issuerShortNames = new ArrayList<>();
    private final ResourceRetriever resourceRetriever;

    private final Map<String, IssuerConfiguration> issuers = new HashMap<>();

    private final Map<String, IssuerProperties> issuerPropertiesMap;

    public MultiIssuerConfiguration(Map<String, IssuerProperties> issuerPropertiesMap) {
        this(issuerPropertiesMap, new ProxyAwareResourceRetriever());
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
            return resourceRetriever;
    }

    private void loadIssuerConfigurations() {

        issuerPropertiesMap.forEach((shortName, value) -> {
            issuerShortNames.add(shortName);
            var config = createIssuerConfiguration(shortName, value);
            issuers.put(shortName, config);
            issuers.put(config.getMetaData().getIssuer().toString(), config);
        });
    }

    private IssuerConfiguration createIssuerConfiguration(String shortName, IssuerProperties issuerProperties) {
        if (issuerProperties.getUsePlaintextForHttps() || issuerProperties.getProxyUrl() != null){
            var resourceRetrieverWithProxy = new ProxyAwareResourceRetriever(issuerProperties.getProxyUrl(), issuerProperties.getUsePlaintextForHttps());
            return new IssuerConfiguration(shortName, issuerProperties, resourceRetrieverWithProxy);
        }
        return new IssuerConfiguration(shortName, issuerProperties, resourceRetriever);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [issuerShortNames=" + issuerShortNames + ", resourceRetriever="
            + resourceRetriever + ", issuers=" + issuers + ", issuerPropertiesMap=" + issuerPropertiesMap + "]";
    }
}