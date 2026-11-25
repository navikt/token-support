package no.nav.security.token.support.client.core

import io.kotest.assertions.assertSoftly
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.longs.shouldBeInRange
import io.kotest.matchers.shouldBe
import java.util.concurrent.TimeUnit.NANOSECONDS
import java.util.concurrent.TimeUnit.SECONDS
import no.nav.security.token.support.client.core.oauth2.OAuth2CacheFactory.accessTokenResponseCache
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse

internal class OAuth2CacheFactoryTest : BehaviorSpec({
    Given("levetider for tilgangstoken rundt den konfigurerte utløpsmarginen") {
        listOf(
            Triple(10, 2L, 8L),
            Triple(2, 2L, 2L),
            Triple(1, 2L, 1L),
            Triple(10, 0L, 10L)
        ).forEach { (expiresIn, skew, expectedLifetime) ->
            When("et token mellomlagres med expires_in=$expiresIn og utløpsmargin=$skew") {
                Then("skal utløpe etter $expectedLifetime sekunder") {
                    val cache = accessTokenResponseCache<String>(10, skew)
                    val response = OAuth2AccessTokenResponse("access", expires_in = expiresIn)
                    val before = System.nanoTime()
                    cache.put("key", response)
                    val remaining = cache.policy().expireVariably().orElseThrow()
                        .getExpiresAfter("key", NANOSECONDS).asLong
                    val elapsed = System.nanoTime() - before
                    val expected = SECONDS.toNanos(expectedLifetime)
                    assertSoftly(cache) {
                        getIfPresent("key") shouldBe response
                        remaining.shouldBeInRange((expected - elapsed).coerceAtLeast(0)..expected)
                    }
                }
            }
        }
    }

    Given("et mellomlagret token uten gjenværende levetid") {
        When("tokenet settes inn") {
            Then("skal la det utløpe umiddelbart") {
                val cache = accessTokenResponseCache<String>(10, 1)
                cache.put("key", OAuth2AccessTokenResponse("access", expires_in = 0))
                cache.getIfPresent("key") shouldBe null
            }
        }
    }

    Given("et mellomlager begrenset til to oppføringer") {
        When("tre token settes inn") {
            Then("skal håndheve maksimal størrelse") {
                val cache = accessTokenResponseCache<String>(2, 1)
                repeat(3) { cache.put("key$it", OAuth2AccessTokenResponse("access$it", expires_in = 60)) }
                cache.cleanUp()
                assertSoftly(cache) {
                    policy().eviction().orElseThrow().maximum shouldBe 2L
                    estimatedSize() shouldBe 2L
                }
            }
        }
    }

    Given("en eksisterende oppføring i mellomlageret") {
        When("oppføringen leses") {
            Then("skal ikke forlenge utløpstiden") {
                val cache = accessTokenResponseCache<String>(10, 1)
                val response = OAuth2AccessTokenResponse("access", expires_in = 60)
                cache.put("key", response)
                val expiry = cache.policy().expireVariably().orElseThrow()
                val before = System.nanoTime()
                val beforeRead = expiry.getExpiresAfter("key", NANOSECONDS).asLong
                val cached = cache.getIfPresent("key")
                val afterRead = expiry.getExpiresAfter("key", NANOSECONDS).asLong
                val elapsed = System.nanoTime() - before
                assertSoftly(cache) {
                    cached shouldBe response
                    afterRead.shouldBeInRange((beforeRead - elapsed).coerceAtLeast(0)..beforeRead)
                }
            }
        }
        When("oppføringen oppdateres med et token med lengre levetid") {
            Then("skal bevare den opprinnelige utløpstiden") {
                val cache = accessTokenResponseCache<String>(10, 1)
                cache.put("key", OAuth2AccessTokenResponse("first", expires_in = 60))
                val expiry = cache.policy().expireVariably().orElseThrow()
                val before = System.nanoTime()
                val beforeUpdate = expiry.getExpiresAfter("key", NANOSECONDS).asLong
                val updated = OAuth2AccessTokenResponse("second", expires_in = 120)
                cache.put("key", updated)
                val afterUpdate = expiry.getExpiresAfter("key", NANOSECONDS).asLong
                val elapsed = System.nanoTime() - before
                assertSoftly(cache) {
                    getIfPresent("key") shouldBe updated
                    afterUpdate.shouldBeInRange((beforeUpdate - elapsed).coerceAtLeast(0)..beforeUpdate)
                }
            }
        }
    }
})
