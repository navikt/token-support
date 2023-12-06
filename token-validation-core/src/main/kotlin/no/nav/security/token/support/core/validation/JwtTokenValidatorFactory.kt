package no.nav.security.token.support.core.validation

import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.ResourceRetriever
import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import java.net.MalformedURLException
import java.net.URL
import no.nav.security.token.support.core.configuration.IssuerProperties
import no.nav.security.token.support.core.exceptions.MetaDataNotAvailableException

object JwtTokenValidatorFactory {

    @JvmStatic
    fun tokenValidator(p : IssuerProperties, md : AuthorizationServerMetadata, retriever : ResourceRetriever) = tokenValidator(p, md, jwkSource(p, md.jwkSetURI.toURL(), retriever))

    @JvmStatic
    fun tokenValidator(p : IssuerProperties, md : AuthorizationServerMetadata, remoteJWKSet : JWKSource<SecurityContext>) =
        DefaultConfigurableJwtValidator(md.issuer.value, p.acceptedAudience, p.validation.optionalClaims, remoteJWKSet)

    private fun jwkSource(p: IssuerProperties, jwksUrl: URL, retriever: ResourceRetriever) =
        JWKSourceBuilder.create<SecurityContext>(jwksUrl, retriever).apply {
            if (p.jwksCache.isConfigured) {
                cache(p.jwksCache.lifespanMillis, p.jwksCache.refreshTimeMillis)
            }
        }.build()
}