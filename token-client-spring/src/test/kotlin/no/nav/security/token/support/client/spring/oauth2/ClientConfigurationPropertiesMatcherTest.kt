package no.nav.security.token.support.client.spring.oauth2

import io.kotest.assertions.assertSoftly
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.net.URI
import no.nav.security.token.support.client.spring.ClientConfigurationProperties

internal class ClientConfigurationPropertiesMatcherTest : BehaviorSpec({
    val registration = TestUtils.clientProperties()
    val properties = ClientConfigurationProperties(mapOf("resource" to registration))
    val matcher = object : ClientConfigurationPropertiesMatcher {}

    Given("en vertsnavnmatcher") {
        When("den første delen av vertsnavnet matcher en registrering") {
            Then("skal returnere samme registrering for inndata av typene String og URI") {
                val uri = URI.create("https://resource.example:8443/api?query=value")
                assertSoftly(matcher) {
                    findProperties(properties, uri) shouldBe registration
                    findProperties(properties, uri.toString()) shouldBe registration
                }
            }
        }
        When("vertsnavnet ikke har punktum") {
            Then("skal matche hele vertsnavnet") {
                matcher.findProperties(properties, "http://resource/api") shouldBe registration
            }
        }
        When("vertsnavnet ikke er registrert") {
            Then("skal ikke returnere noen match") {
                matcher.findProperties(properties, "https://unknown.example/resource") shouldBe null
            }
        }
        When("det ikke finnes registreringer") {
            Then("skal ikke returnere noen match") {
                matcher.findProperties(ClientConfigurationProperties(emptyMap()), "https://resource.example") shouldBe null
            }
        }
        When("strengen ikke er en gyldig URI") {
            Then("skal avvise den") {
                shouldThrow<IllegalArgumentException> {
                    matcher.findProperties(properties, "https://invalid host/api")
                }
            }
        }
        When("URI-en ikke har en vert") {
            listOf("/api/resource", "mailto:resource@example.com", "https:///api").forEach { uri ->
                Then("skal eksplisitt avvise $uri") {
                    val exception = shouldThrow<IllegalArgumentException> {
                        matcher.findProperties(properties, URI.create(uri))
                    }
                    assertSoftly(exception) {
                        message shouldContain "Request URI must have a host"
                        message shouldContain uri
                    }
                }
            }
        }
    }
})
