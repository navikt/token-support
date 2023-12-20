package no.nav.security.token.support.core.configuration

import com.nimbusds.jose.util.ResourceRetriever
import java.util.Optional
import kotlin.DeprecationLevel.WARNING

class MultiIssuerConfiguration @JvmOverloads constructor(private val properties : Map<String, IssuerProperties>, val retriever : ResourceRetriever = ProxyAwareResourceRetriever()) {

    val issuerShortNames = ArrayList<String>()

    val issuers : MutableMap<String, IssuerConfiguration> = HashMap()

    init {
        loadIssuerConfigurations()
    }
    @Deprecated(message ="Use of Optional not necessary",ReplaceWith("getIssuers.get(<issuer>)"), WARNING)
    fun getIssuer(name : String) = Optional.ofNullable(issuers[name])

    private fun loadIssuerConfigurations() =
        properties.forEach { (shortName, p) ->
             createIssuerConfiguration(shortName, p).run {
                issuerShortNames.add(shortName)
                issuers[shortName] = this
                issuers["${metadata.issuer}"] = this
            }
        }

    private fun createIssuerConfiguration(shortName : String, p : IssuerProperties) =
        if (p.usePlaintextForHttps || p.proxyUrl != null) {
            IssuerConfiguration(shortName, p, ProxyAwareResourceRetriever(p.proxyUrl, p.usePlaintextForHttps))
        }
        else IssuerConfiguration(shortName, p, retriever)

    override fun toString() = ("${javaClass.simpleName} [issuerShortNames=$issuerShortNames, resourceRetriever=$retriever, issuers=$issuers, issuerPropertiesMap=$properties]")
}