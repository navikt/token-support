package no.nav.security.token.support.client.core

import com.github.benmanes.caffeine.cache.Caffeine
import com.github.benmanes.caffeine.cache.Expiry
import java.util.concurrent.TimeUnit.SECONDS
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse

object OAuth2CacheFactory {

    @JvmStatic
    fun <T> accessTokenResponseCache(maximumSize : Long, skewInSeconds : Long) =
        // Evict based on a varying expiration policy
        Caffeine.newBuilder()
            .maximumSize(maximumSize)
            .expireAfter(evictOnResponseExpiresIn<Any>(skewInSeconds))
            .build<T, OAuth2AccessTokenResponse>()

    private fun <T> evictOnResponseExpiresIn(skewInSeconds : Long) : Expiry<T, OAuth2AccessTokenResponse> {
        return object : Expiry<T, OAuth2AccessTokenResponse> {
            override fun expireAfterCreate(key : T, response : OAuth2AccessTokenResponse, currentTime : Long) =
                SECONDS.toNanos(if (response.expiresIn > skewInSeconds) response.expiresIn - skewInSeconds else response.expiresIn.toLong())

            override fun expireAfterUpdate(key : T, response : OAuth2AccessTokenResponse, currentTime : Long, currentDuration : Long) = currentDuration
            override fun expireAfterRead(key : T, response : OAuth2AccessTokenResponse, currentTime : Long, currentDuration : Long) = currentDuration
        }
    }
}