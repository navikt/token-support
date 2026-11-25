package no.nav.security.token.support.client.spring.oauth2

import io.kotest.assertions.assertSoftly
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.shouldBe
import java.net.URI
import no.nav.security.token.support.client.spring.ClientConfigurationProperties

internal class PathPrefixClientConfigurationPropertiesMatcherTest : BehaviorSpec({
    val general = TestUtils.clientProperties("general")
    val specific = TestUtils.clientProperties("specific")
    val properties = ClientConfigurationProperties(mapOf("general" to general, "specific" to specific))

    Given("overlappende stiprefikser") {
        When("flere prefikser matcher") {
            Then("skal velge det lengste prefikset uavhengig av konfigurasjonsrekkefølgen") {
                val prefixes = listOf("/api" to "general", "/api/resource" to "specific")
                val uri = URI.create("https://unregistered.example/api/resource/123?query=value")
                assertSoftly(properties) {
                    PathPrefixClientConfigurationPropertiesMatcher(prefixes)
                        .findProperties(this, uri) shouldBe specific
                    PathPrefixClientConfigurationPropertiesMatcher(prefixes.reversed())
                        .findProperties(this, uri.toString()) shouldBe specific
                }
            }
        }
        When("bare det kortere prefikset matcher") {
            Then("skal returnere registreringen som tilhører det") {
                PathPrefixClientConfigurationPropertiesMatcher(
                    listOf("/api" to "general", "/api/resource" to "specific")
                ).findProperties(properties, "/api/other") shouldBe general
            }
        }
        When("det lengste prefikset peker på en ukjent registrering") {
            Then("skal ikke returnere noen match fremfor å falle tilbake til et kortere prefiks") {
                PathPrefixClientConfigurationPropertiesMatcher(
                    listOf("/api" to "general", "/api/resource" to "missing")
                ).findProperties(properties, "/api/resource") shouldBe null
            }
        }
    }

    Given("en stiprefiksmatcher") {
        When("ingen prefikser matcher stien") {
            Then("skal ignorere samsvarende tekst i vertsnavnet og spørringen") {
                PathPrefixClientConfigurationPropertiesMatcher(listOf("/api" to "general"))
                    .findProperties(properties, "https://api.example/other?redirect=/api") shouldBe null
            }
        }
        When("ingen prefikser er konfigurert") {
            Then("skal ikke returnere noen match") {
                PathPrefixClientConfigurationPropertiesMatcher(emptyList())
                    .findProperties(properties, "/api/resource") shouldBe null
            }
        }
        When("URI-en ikke har en sti") {
            Then("skal ikke returnere noen match, selv for et tomt prefiks") {
                PathPrefixClientConfigurationPropertiesMatcher(listOf("" to "general"))
                    .findProperties(properties, "mailto:resource@example.com") shouldBe null
            }
        }
        When("stien er nøyaktig lik et prefiks") {
            Then("skal returnere registreringen som tilhører det") {
                PathPrefixClientConfigurationPropertiesMatcher(listOf("/api/resource" to "specific"))
                    .findProperties(properties, "/api/resource") shouldBe specific
            }
        }
    }
})
