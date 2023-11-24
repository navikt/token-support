package no.nav.security.token.support.client.core.http

import java.net.URI
import java.util.Collections.unmodifiableMap

class OAuth2HttpRequest (val tokenEndpointUrl : URI?, val oAuth2HttpHeaders : OAuth2HttpHeaders?, val formParameters : Map<String, String>) {


    class OAuth2HttpRequestBuilder @JvmOverloads constructor (private var tokenEndpointUrl : URI? = null,
        private var oAuth2HttpHeaders : OAuth2HttpHeaders? = null,
        private var keys : MutableList<String> = mutableListOf(),
        private var values: MutableList<String> = mutableListOf()) {
        fun tokenEndpointUrl(tokenEndpointUrl : URI?) : OAuth2HttpRequestBuilder {
            this.tokenEndpointUrl = tokenEndpointUrl
            return this
        }

        fun oAuth2HttpHeaders(oAuth2HttpHeaders : OAuth2HttpHeaders?) : OAuth2HttpRequestBuilder {
            this.oAuth2HttpHeaders = oAuth2HttpHeaders
            return this
        }

        fun formParameter(formParameterKey : String, formParameterValue : String) : OAuth2HttpRequestBuilder {
            keys.add(formParameterKey)
            values.add(formParameterValue)
            return this
        }

        fun formParameters(formParameters : Map<out String, String>) : OAuth2HttpRequestBuilder {
            formParameters.forEach { (key, value) ->
                keys.add(key)
                values.add(value)
            }
            return this
        }

        fun clearFormParameters() : OAuth2HttpRequestBuilder {
            keys.clear()
            values.clear()
            return this
        }

        fun build() : OAuth2HttpRequest {
            return when (keys.size) {
                0 -> OAuth2HttpRequest(tokenEndpointUrl, oAuth2HttpHeaders, mapOf())
                1 -> OAuth2HttpRequest(tokenEndpointUrl, oAuth2HttpHeaders, mapOf(Pair(keys[0], values[0])))
                else -> {
                    val formParameters : LinkedHashMap<String, String> = LinkedHashMap<String, String>(keys.size)
                    var i = 0
                    while (i < keys.size) {
                        formParameters.put(keys[i], values[i])
                        i++
                    }
                    OAuth2HttpRequest(tokenEndpointUrl, oAuth2HttpHeaders, unmodifiableMap(formParameters))
                }
            }
        }

        @Override
        override fun toString() : String {
            return "OAuth2HttpRequest.OAuth2HttpRequestBuilder(tokenEndpointUrl=$tokenEndpointUrl, oAuth2HttpHeaders=$oAuth2HttpHeaders, keys=$keys, values=$values)"
        }
    }

    companion object {

        fun builder() : OAuth2HttpRequestBuilder {
            return OAuth2HttpRequestBuilder()
        }
    }
}