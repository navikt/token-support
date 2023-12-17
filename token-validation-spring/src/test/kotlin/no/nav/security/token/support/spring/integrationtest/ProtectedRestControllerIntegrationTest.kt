package no.nav.security.token.support.spring.integrationtest

import com.nimbusds.jose.JOSEObjectType.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.oauth2.sdk.TokenRequest
import io.restassured.module.mockmvc.RestAssuredMockMvc
import io.restassured.module.mockmvc.RestAssuredMockMvc.webAppContextSetup
import jakarta.servlet.Filter
import java.util.Date
import java.util.UUID
import java.util.concurrent.TimeUnit.MINUTES
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.runner.ApplicationContextRunner
import org.springframework.http.HttpStatus
import org.springframework.http.HttpStatus.OK
import org.springframework.http.HttpStatus.UNAUTHORIZED
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.web.servlet.setup.ConfigurableMockMvcBuilder
import org.springframework.test.web.servlet.setup.MockMvcConfigurer
import org.springframework.web.context.WebApplicationContext
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.token.OAuth2TokenCallback
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.spring.SpringTokenValidationContextHolder
import no.nav.security.token.support.spring.integrationtest.AProtectedRestController.Companion.PROTECTED
import no.nav.security.token.support.spring.integrationtest.AProtectedRestController.Companion.PROTECTED_WITH_CLAIMS
import no.nav.security.token.support.spring.integrationtest.AProtectedRestController.Companion.PROTECTED_WITH_CLAIMS2
import no.nav.security.token.support.spring.integrationtest.AProtectedRestController.Companion.PROTECTED_WITH_CLAIMS_ANY_CLAIMS
import no.nav.security.token.support.spring.integrationtest.AProtectedRestController.Companion.PROTECTED_WITH_MULTIPLE
import no.nav.security.token.support.spring.integrationtest.AProtectedRestController.Companion.UNPROTECTED
import no.nav.security.token.support.spring.integrationtest.JwkGenerator.DEFAULT_KEYID
import no.nav.security.token.support.spring.integrationtest.JwkGenerator.createJWK
import no.nav.security.token.support.spring.integrationtest.JwkGenerator.generateKeyPair
import no.nav.security.token.support.spring.integrationtest.JwtTokenGenerator.ACR
import no.nav.security.token.support.spring.integrationtest.JwtTokenGenerator.AUD
import no.nav.security.token.support.spring.integrationtest.JwtTokenGenerator.createSignedJWT
import no.nav.security.token.support.spring.validation.interceptor.BearerTokenClientHttpRequestInterceptor

private const val PROP = "no.nav.security.jwt.dont-propagate-bearertoken"

@SpringBootTest
@ContextConfiguration(classes = [ProtectedApplication::class, ProtectedApplicationConfig::class])
@ActiveProfiles("test")
internal class ProtectedRestControllerIntegrationTest {
    @Autowired
    private lateinit var ctx: WebApplicationContext

    private lateinit var runner: ApplicationContextRunner

    @Autowired
    private lateinit var mockOAuth2Server: MockOAuth2Server

    @BeforeEach
    fun initialiseRestAssuredMockMvcWebApplicationContext() {
        runner = ApplicationContextRunner()
            .withUserConfiguration(BearerTokenClientHttpRequestInterceptor::class.java, SpringTokenValidationContextHolder::class.java)
        webAppContextSetup(ctx, object : MockMvcConfigurer {
            override fun afterConfigurerAdded(builder: ConfigurableMockMvcBuilder<*>) {
                builder.addFilters(*ctx.getBeansOfType(Filter::class.java).values.toTypedArray())
            }
        })
    }

    @Test
    fun registerInterceptorDefault() = runner.run { assertThat(it).hasSingleBean(BearerTokenClientHttpRequestInterceptor::class.java) }

    @Test
    fun registerInterceptorExplicitly() =  runner.withPropertyValues(PROP,"false").run { assertThat(it).hasSingleBean(BearerTokenClientHttpRequestInterceptor::class.java)}
    
    @Test
    fun doNotRegisterInterceptor() = runner.withPropertyValues(PROP,"true").run { assertThat(it).doesNotHaveBean(BearerTokenClientHttpRequestInterceptor::class.java) }


        @Test
    fun unprotectedMethod() {
        RestAssuredMockMvc.given()
            .`when`()[UNPROTECTED]
            .then()
            .log().ifValidationFails()
            .statusCode(OK.value())
    }

    @Test
    fun noTokenInRequest() {
        RestAssuredMockMvc.given()
            .`when`()[PROTECTED]
            .then()
            .log().ifValidationFails()
            .statusCode(UNAUTHORIZED.value())
    }

    @Test
    fun unparseableTokenInRequest() = expectStatusCode(PROTECTED, "unparseable", UNAUTHORIZED)

    @Test
    fun unsignedTokenInRequest() =
        expectStatusCode(PROTECTED, PlainJWT(jwtClaimsSetKnownIssuer()).serialize(), UNAUTHORIZED)

    @Test
    fun signedTokenInRequestUnknownIssuer() =
        expectStatusCode(PROTECTED, issueToken("unknown", jwtClaimsSet(AUD)).serialize(), UNAUTHORIZED)

    @Test
    fun signedTokenInRequestUnknownAudience() =
        expectStatusCode(PROTECTED, issueToken("knownissuer", jwtClaimsSet("unknown")).serialize(), UNAUTHORIZED)

    @Test
    fun signedTokenInRequestProtectedWithClaimsMethodMissingRequiredClaims() = expectStatusCode(
            PROTECTED_WITH_CLAIMS,
            issueToken(
                    "knownissuer", defaultJwtClaimsSetBuilder()
                .claim("importantclaim", "vip")
                .build()).serialize(),
            UNAUTHORIZED)

    @Test
    fun signedTokenInRequestKeyFromUnknownSource() = expectStatusCode(
            PROTECTED,
            createSignedJWT(createJWK(DEFAULT_KEYID, generateKeyPair()), jwtClaimsSetKnownIssuer()).serialize(),
            UNAUTHORIZED)

    @Test
    fun signedTokenInRequestProtectedMethodShouldBeOk() =
        expectStatusCode(PROTECTED, issueToken("knownissuer", jwtClaimsSetKnownIssuer()).serialize(), OK)


    @Test
    @DisplayName("Token matches one of the configured issuers, including claims")
    fun multipleIssuersOneOKIncludingClaims() = expectStatusCode(
            PROTECTED_WITH_MULTIPLE,
            issueToken(
                    "knownissuer", defaultJwtClaimsSetBuilder()
                .claim("claim1", "3")
                .claim("claim2", "4")
                .claim("acr", "Level4")
                .build()).serialize(), OK)


    @Test
    @DisplayName("Token matches one of the configured issuers, but not all claims match")
    fun multipleIssuersOneIssuerMatchesButClaimsDont() = expectStatusCode(
            PROTECTED_WITH_MULTIPLE,
            issueToken("knownissuer", jwtClaimsSetKnownIssuer()).serialize(),
            UNAUTHORIZED)


    @Test
    @DisplayName("Token matches none of the configured issuers")
    fun multipleIssuersNoIssuerMatches() = expectStatusCode(
            PROTECTED_WITH_MULTIPLE,
            issueToken("knownissuer3", jwtClaimsSetKnownIssuer()).serialize(),
            UNAUTHORIZED)


    @Test
    fun signedTokenInRequestProtectedWithClaimsMethodShouldBeOk() {
        expectStatusCode(
                PROTECTED_WITH_CLAIMS,
                issueToken(
                        "knownissuer", defaultJwtClaimsSetBuilder()
                    .claim("importantclaim", "vip")
                    .claim("acr", "Level4")
                    .build()).serialize(), OK)
        expectStatusCode(
                PROTECTED_WITH_CLAIMS_ANY_CLAIMS,
                issueToken(
                        "knownissuer", defaultJwtClaimsSetBuilder()
                    .claim("claim1", "1")
                    .build()).serialize(), OK)
    }

    @Test
    fun signedTokenInRequestProtectedWithArrayClaimsMethodShouldBeOk() = expectStatusCode(
            PROTECTED_WITH_CLAIMS_ANY_CLAIMS,
            issueToken(
                    "knownissuer", defaultJwtClaimsSetBuilder()
                .claim("claim1", listOf("1"))
                .build()).serialize(), OK)


    @Test
    fun signedTokenInRequestWithoutSubAndAudClaimsShouldBeOk() {
        val now = Date()
        expectStatusCode(
                PROTECTED_WITH_CLAIMS2,
                issueToken(
                        "knownissuer2", Builder()
                    .jwtID(UUID.randomUUID().toString())
                    .claim("auth_time", now)
                    .notBeforeTime(now)
                    .issueTime(now)
                    .expirationTime(Date(now.time + MINUTES.toMillis(1)))
                    .build()).serialize(),
                OK)
    }

    @Test
    fun signedTokenInRequestWithoutSubAndAudClaimsShouldBeNotBeOk() {
        val now = Date()
        val jwtClaimsSet = Builder()
            .jwtID(UUID.randomUUID().toString())
            .claim("auth_time", now)
            .notBeforeTime(now)
            .issueTime(now)
            .expirationTime(Date(now.time + MINUTES.toMillis(1)))
            .build()
        expectStatusCode(
                PROTECTED_WITH_CLAIMS,
                issueToken("knownissuer", jwtClaimsSet).serialize(),
                UNAUTHORIZED)
    }

    private fun issueToken(issuerId: String, jwtClaimsSet: JWTClaimsSet) =
        mockOAuth2Server.issueToken(issuerId, "client_id", object : OAuth2TokenCallback {
            override fun typeHeader(tokenRequest: TokenRequest) = JWT.type
            override fun tokenExpiry() = 30L
            override fun subject(tokenRequest: TokenRequest) = jwtClaimsSet.subject
            override fun issuerId() = issuerId
            override fun audience(tokenRequest: TokenRequest) = jwtClaimsSet.audience
            override fun addClaims(tokenRequest: TokenRequest) = jwtClaimsSet.claims
        })


    companion object {
        private fun expectStatusCode(uri: String, token: String, httpStatus: HttpStatus) =
            RestAssuredMockMvc.given()
                .header(AUTHORIZATION_HEADER, "Bearer $token")
                .`when`()[uri]
                .then()
                .log().ifValidationFails()
                .statusCode(httpStatus.value())


        private fun defaultJwtClaimsSetBuilder(): Builder {
            val now = Date()
            return Builder()
                .subject("testsub")
                .audience(AUD)
                .jwtID(UUID.randomUUID().toString())
                .claim("auth_time", now)
                .notBeforeTime(now)
                .issueTime(now)
                .expirationTime(Date(now.time + MINUTES.toMillis(1)))
        }

        private fun jwtClaimsSetKnownIssuer() = jwtClaimsSet(AUD)

        private fun jwtClaimsSet(audience: String) = buildClaimSet("testsub", audience, ACR, MINUTES.toMillis(1))


        fun buildClaimSet(subject: String?, audience: String?, authLevel: String?,
                          expiry: Long): JWTClaimsSet {
            val now = Date()
            return Builder()
                .subject(subject)
                .audience(audience)
                .jwtID(UUID.randomUUID().toString())
                .claim("acr", authLevel)
                .claim("ver", "1.0")
                .claim("nonce", "myNonce")
                .claim("auth_time", now)
                .notBeforeTime(now)
                .issueTime(now)
                .expirationTime(Date(now.time + expiry)).build()
        }
    }
}