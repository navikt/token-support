package no.nav.security.token.support.core.configuration

import com.nimbusds.jose.util.ResourceRetriever
import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import java.net.URL
import no.nav.security.token.support.core.exceptions.MetaDataNotAvailableException
import no.nav.security.token.support.core.validation.JwtTokenValidator
import no.nav.security.token.support.core.validation.JwtTokenValidatorFactory.tokenValidator

open class IssuerConfiguration(val name : String, issuerProperties : IssuerProperties, retriever : ResourceRetriever?) {

    val metadata : AuthorizationServerMetadata
    val acceptedAudience  = issuerProperties.acceptedAudience
    val cookieName = issuerProperties.cookieName
    val headerName = issuerProperties.headerName
    val tokenValidator : JwtTokenValidator
    val resourceRetriever = retriever ?: ProxyAwareResourceRetriever()

    init {
        this.metadata = providerMetadata(resourceRetriever, issuerProperties.discoveryUrl)
        this.tokenValidator = tokenValidator(issuerProperties, metadata, resourceRetriever)
    }

    override fun toString() = ("${javaClass.simpleName} [name=$name, metaData=$metadata, acceptedAudience=$acceptedAudience, cookieName=$cookieName, headerName=$headerName, tokenValidator=$tokenValidator, resourceRetriever=$resourceRetriever]")

    companion object {

        protected fun providerMetadata(resourceRetriever : ResourceRetriever, url : URL?) =
            runCatching {
                AuthorizationServerMetadata.parse(resourceRetriever.retrieveResource(url).content)
            }.getOrElse {
                throw MetaDataNotAvailableException("Make sure you are not using proxying in GCP", url, it)
            }
    }
}