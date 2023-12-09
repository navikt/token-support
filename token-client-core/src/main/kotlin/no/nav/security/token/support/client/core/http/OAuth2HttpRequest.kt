package no.nav.security.token.support.client.core.http

import java.net.URI
import java.util.Collections.unmodifiableMap

class OAuth2HttpRequest (val tokenEndpointUrl : URI?, val oAuth2HttpHeaders : OAuth2HttpHeaders?, val formParameters : Map<String, String>) {


    class OAuth2HttpRequestBuilder @JvmOverloads constructor(private var tokenEndpointUrl: URI?,
                                                              private var oAuth2HttpHeaders : OAuth2HttpHeaders? = null,
                                                              private var formParameters: MutableMap<String,String> = mutableMapOf()) {
        fun tokenEndpointUrl(tokenEndpointUrl : URI?) = this.also { it.tokenEndpointUrl = tokenEndpointUrl }

        fun oAuth2HttpHeaders(oAuth2HttpHeaders : OAuth2HttpHeaders?) = this.also { it.oAuth2HttpHeaders = oAuth2HttpHeaders }

        fun formParameter(key : String, value : String) = this.also { formParameters[key] = value }

        fun formParameters(entries: Map<out String, String>): OAuth2HttpRequestBuilder = this.also { formParameters.putAll(entries) }

        fun build(): OAuth2HttpRequest  = OAuth2HttpRequest(tokenEndpointUrl, oAuth2HttpHeaders, unmodifiableMap(formParameters))

        @Override
        override fun toString() = "OAuth2HttpRequest.OAuth2HttpRequestBuilder(tokenEndpointUrl=$tokenEndpointUrl, oAuth2HttpHeaders=$oAuth2HttpHeaders, entries=$formParameters"


    }
    companion object {
        fun builder( tokenEndpointUrl: URI?) = OAuth2HttpRequestBuilder(tokenEndpointUrl)

    }
}