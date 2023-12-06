package no.nav.security.token.support.core.configuration

import com.nimbusds.jose.util.ResourceRetriever
import java.util.Optional

class MultiIssuerConfiguration @JvmOverloads constructor(private val issuerPropertiesMap : Map<String, IssuerProperties>,
                                                         val resourceRetriever : ResourceRetriever = ProxyAwareResourceRetriever()) {

    private val issuerShortNames : MutableList<String> = ArrayList()

    val issuers : MutableMap<String, IssuerConfiguration> = HashMap()

    init {
        loadIssuerConfigurations()
    }

    fun getIssuer(name : String) = Optional.ofNullable(issuers[name])

    fun getIssuerShortNames() = issuerShortNames

    private fun loadIssuerConfigurations() {
        issuerPropertiesMap.forEach { (shortName, value) ->
            issuerShortNames.add(shortName)
            val config = createIssuerConfiguration(shortName, value)
            issuers[shortName] = config
            issuers[config.metadata.issuer.toString()] = config
        }
    }

    private fun createIssuerConfiguration(shortName : String, p : IssuerProperties) : IssuerConfiguration {
        if (p.usePlaintextForHttps || p.proxyUrl != null) {
            return IssuerConfiguration(shortName, p, ProxyAwareResourceRetriever(p.proxyUrl, p.usePlaintextForHttps))
        }
        return IssuerConfiguration(shortName, p, resourceRetriever)
    }

    override fun toString() : String {
        return (javaClass.simpleName + " [issuerShortNames=" + issuerShortNames + ", resourceRetriever="
            + resourceRetriever + ", issuers=" + issuers + ", issuerPropertiesMap=" + issuerPropertiesMap + "]")
    }
}