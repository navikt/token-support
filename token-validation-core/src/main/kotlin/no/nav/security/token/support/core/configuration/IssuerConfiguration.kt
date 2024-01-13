package no.nav.security.token.support.core.configuration

import com.nimbusds.jose.util.ResourceRetriever
import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import java.net.URL
import no.nav.security.token.support.core.exceptions.MetaDataNotAvailableException
import no.nav.security.token.support.core.validation.JwtTokenValidator
import no.nav.security.token.support.core.validation.JwtTokenValidatorFactory.tokenValidator

open class IssuerConfiguration(val name : String, properties : IssuerProperties, val resourceRetriever : ResourceRetriever = ProxyAwareResourceRetriever()) {

    val metadata : AuthorizationServerMetadata
    val acceptedAudience  = properties.acceptedAudience
    val headerName = properties.headerName
    val tokenValidator : JwtTokenValidator

    init {
        metadata = providerMetadata(resourceRetriever, properties.discoveryUrl)
        tokenValidator = tokenValidator(properties, metadata, resourceRetriever)
    }

    override fun toString() = ("${javaClass.simpleName} [name=$name, metaData=$metadata, acceptedAudience=$acceptedAudience, headerName=$headerName, tokenValidator=$tokenValidator, resourceRetriever=$resourceRetriever]")

    companion object {

        private fun providerMetadata(retriever : ResourceRetriever, url : URL) =
            runCatching {
                AuthorizationServerMetadata.parse(retriever.retrieveResource(url).content)
            }.getOrElse {
                throw MetaDataNotAvailableException("Make sure you are not using proxying in GCP", url, it)
            }
    }
}