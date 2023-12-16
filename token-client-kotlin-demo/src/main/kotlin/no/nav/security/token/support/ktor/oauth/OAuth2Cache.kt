package no.nav.security.token.support.ktor.oauth

import com.github.benmanes.caffeine.cache.AsyncLoadingCache
import com.github.benmanes.caffeine.cache.Caffeine
import com.github.benmanes.caffeine.cache.Expiry
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.future.future
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse
import java.util.concurrent.TimeUnit

data class OAuth2CacheConfig(val enabled: Boolean, val maximumSize: Long = 1000, val evictSkew: Long = 5) {
    fun cache(cacheContext: CoroutineScope, loader: suspend (GrantRequest) -> OAuth2AccessTokenResponse): AsyncLoadingCache<GrantRequest, OAuth2AccessTokenResponse> =
        Caffeine.newBuilder()
            .expireAfter(evictOnResponseExpiresIn(evictSkew))
            .maximumSize(maximumSize)
            .buildAsync { key: GrantRequest, _ ->
                cacheContext.future {
                    loader(key)
                }
            }

    private fun evictOnResponseExpiresIn(skewInSeconds: Long): Expiry<GrantRequest, OAuth2AccessTokenResponse> {
        return object : Expiry<GrantRequest, OAuth2AccessTokenResponse> {

            override fun expireAfterCreate(key: GrantRequest, response: OAuth2AccessTokenResponse, currentTime: Long): Long {
                val seconds =
                    if (response.expiresIn!! > skewInSeconds) response.expiresIn!! - skewInSeconds else response.expiresIn!!
                        .toLong()
                return TimeUnit.SECONDS.toNanos(seconds)
            }

            override fun expireAfterUpdate(key: GrantRequest, response: OAuth2AccessTokenResponse, currentTime: Long, currentDuration: Long): Long = currentDuration


            override fun expireAfterRead(key: GrantRequest, response: OAuth2AccessTokenResponse, currentTime: Long, currentDuration: Long): Long = currentDuration
        }
    }
}