package no.nav.security.token.support.client.spring.oauth2

import io.kotest.assertions.assertSoftly
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import jakarta.validation.Validation
import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver
import no.nav.security.token.support.client.core.http.OAuth2HttpClient
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.springframework.boot.context.properties.ConfigurationPropertiesBindException
import org.springframework.boot.test.context.FilteredClassLoader
import org.springframework.boot.test.context.runner.ApplicationContextRunner

internal class OAuth2ClientConfigurationTest : BehaviorSpec({
    val prefix = "no.nav.security.jwt.client.registration.resource"
    val validProperties = arrayOf(
        "$prefix.token-endpoint-url=https://tokens.example/token",
        "$prefix.grant-type=client_credentials",
        "$prefix.authentication.client-id=client",
        "$prefix.authentication.client-secret=secret",
        "$prefix.authentication.client-auth-method=client_secret_basic"
    )
    val runner = ApplicationContextRunner()
        .withUserConfiguration(ConfigurationWithCacheEnabledFalse::class.java)
        .withPropertyValues(*validProperties)
    val holder = mock<TokenValidationContextHolder>()

    Given("standard klientkonfigurasjon for Spring") {
        When("ingen egendefinert HTTP-klient er registrert") {
            Then("skal registrere én standardklient og interceptoren") {
                runner.withBean(TokenValidationContextHolder::class.java, { holder }).run { context ->
                    context.startupFailure shouldBe null
                    assertSoftly(context) {
                        getBeansOfType(OAuth2HttpClient::class.java).values.shouldHaveSize(1)
                        getBean(OAuth2HttpClient::class.java).shouldBeInstanceOf<DefaultOAuth2HttpClient>()
                        getBeansOfType(OAuth2ClientRequestInterceptor::class.java).values.shouldHaveSize(1)
                        getBeansOfType(OAuth2AccessTokenService::class.java).values.shouldHaveSize(1)
                    }
                }
            }
        }
        When("en egendefinert HTTP-klient er registrert") {
            Then("skal beholde den uten å registrere standardklienten") {
                val customClient = mock<OAuth2HttpClient>()
                runner.withBean(TokenValidationContextHolder::class.java, { holder })
                    .withBean(OAuth2HttpClient::class.java, { customClient })
                    .run { context ->
                        context.startupFailure shouldBe null
                        assertSoftly(context) {
                            getBeansOfType(OAuth2HttpClient::class.java).values.shouldHaveSize(1)
                            getBean(OAuth2HttpClient::class.java) shouldBe customClient
                            getBeansOfType(DefaultOAuth2HttpClient::class.java).values.shouldHaveSize(0)
                        }
                    }
            }
        }
        When("tokenvalideringskonteksten ikke inneholder gyldige token") {
            Then("skal ikke finne noe subjekttoken") {
                whenever(holder.getTokenValidationContext()).thenReturn(TokenValidationContext(emptyMap()))
                runner.withBean(TokenValidationContextHolder::class.java, { holder }).run { context ->
                    context.startupFailure shouldBe null
                    context.getBean(JwtBearerTokenResolver::class.java).token() shouldBe null
                }
            }
        }
    }

    Given("tokenvalidering ikke finnes på klassestien") {
        When("ingen egendefinert tokenoppløser er registrert") {
            Then("skal registrere en reservetokenoppløser som eksplisitt avviser tokenoppløsning") {
                runner.withClassLoader(FilteredClassLoader(TokenValidationContextHolder::class.java)).run { context ->
                    context.startupFailure shouldBe null
                    context.getBeansOfType(JwtBearerTokenResolver::class.java).values.shouldHaveSize(1)
                    val resolver = context.getBean(JwtBearerTokenResolver::class.java)
                    shouldThrow<UnsupportedOperationException> { resolver.token() }
                        .message shouldContain "no-op implementation"
                }
            }
        }
        When("en egendefinert tokenoppløser er registrert") {
            Then("skal bruke den i stedet for reservetokenoppløseren") {
                val customResolver = JwtBearerTokenResolver { "custom-subject" }
                runner.withClassLoader(FilteredClassLoader(TokenValidationContextHolder::class.java))
                    .withBean(JwtBearerTokenResolver::class.java, { customResolver })
                    .run { context ->
                        context.startupFailure shouldBe null
                        assertSoftly(context) {
                            getBeansOfType(JwtBearerTokenResolver::class.java).values.shouldHaveSize(1)
                            getBean(JwtBearerTokenResolver::class.java) shouldBe customResolver
                            getBean(JwtBearerTokenResolver::class.java).token() shouldBe "custom-subject"
                        }
                    }
            }
        }
    }

    Given("ugyldige klientregistreringsegenskaper") {
        When("et tomt registreringsmap valideres") {
            Then("skal rapportere et brudd på registreringskravene") {
                Validation.buildDefaultValidatorFactory().use { factory ->
                    val violations = factory.validator.validate(ClientConfigurationProperties(emptyMap()))
                    violations.map { it.propertyPath.toString() } shouldBe listOf("registration")
                }
            }
        }
        When("ingen registreringer er konfigurert") {
            Then("skal feile ved oppstart av konteksten fremfor å opprette en ubrukelig tjeneste") {
                ApplicationContextRunner()
                    .withUserConfiguration(ConfigurationWithCacheEnabledFalse::class.java)
                    .withBean(TokenValidationContextHolder::class.java, { holder })
                    .run { context ->
                        context.startupFailure.shouldNotBeNull().stackTraceToString()
                            .shouldContain("ConfigurationPropertiesBindException")
                    }
            }
        }
        listOf(
            "$prefix.grant-type=authorization_code" to "Unsupported grantType",
            "$prefix.authentication.client-auth-method=none" to "Unsupported authentication method",
            "$prefix.authentication.client-auth-method=private_key_jwt" to "Client private key must be set"
        ).forEach { (invalidProperty, expectedMessage) ->
            When("$invalidProperty bindes") {
                Then("skal rapportere den ugyldige registreringen og årsaken") {
                    runner.withBean(TokenValidationContextHolder::class.java, { holder })
                        .withPropertyValues(invalidProperty)
                        .run { context ->
                            val failure = context.startupFailure.shouldNotBeNull()
                            assertSoftly(failure) {
                                stackTraceToString() shouldContain ConfigurationPropertiesBindException::class.java.simpleName
                                stackTraceToString() shouldContain expectedMessage
                            }
                        }
                }
            }
        }
        When("en registrering med klienthemmelighet mangler hemmeligheten") {
            Then("skal rapportere den manglende legitimasjonen") {
                val propertiesWithoutSecret = validProperties
                    .filterNot { it.startsWith("$prefix.authentication.client-secret=") }
                    .toTypedArray()
                ApplicationContextRunner()
                    .withUserConfiguration(ConfigurationWithCacheEnabledFalse::class.java)
                    .withBean(TokenValidationContextHolder::class.java, { holder })
                    .withPropertyValues(*propertiesWithoutSecret)
                    .run { context ->
                        context.startupFailure.shouldNotBeNull().stackTraceToString()
                            .shouldContain("Client secret must be set")
                    }
            }
        }
    }

    Given("et ikke-tomt registreringsmap med gyldige klientegenskaper") {
        When("egenskapene valideres") {
            Then("skal ikke rapportere noen brudd på kravene") {
                Validation.buildDefaultValidatorFactory().use { factory ->
                    factory.validator.validate(
                        ClientConfigurationProperties(mapOf("resource" to TestUtils.clientProperties()))
                    ).shouldHaveSize(0)
                }
            }
        }
    }
})
