package no.nav.security.token.support.core.validation

import com.nimbusds.jose.JWSAlgorithm.*
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimNames.*
import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import no.nav.security.token.support.core.exceptions.JwtTokenValidatorException

/**
 * The default configurable JwtTokenValidator.
 * Configures sane defaults and delegates verification to [DefaultJwtClaimsVerifier]:
 *
 *
 * The following set of claims are required by default and *must*be present in the JWTs:
 *
 *  * iss - Issuer
 *  * sub - Subject
 *  * aud - Audience
 *  * exp - Expiration Time
 *  * iat - Issued At
 *
 *
 *
 * Otherwise, the following checks are in place:
 *
 *  * The issuer ("iss") claim value must match exactly with the specified accepted issuer value.
 *  * *At least one* of the values in audience ("aud") claim must match one of the specified accepted audiences.
 *  * Time validity checks are performed on the issued at ("iat"), expiration ("exp") and not-before ("nbf") claims if and only if they are present.
 *
 *
 *
 * Note: the not-before ("nbf") claim is *not* a required claim. Conversely, the expiration ("exp") claim *is* a default required claim.
 *
 *
 * Specifying optional claims will *remove* any matching claims from the default set of required claims.
 *
 *
 * Audience validation is only skipped if the claim is explicitly configured as an optional claim, and the list of accepted audiences is empty / not configured.
 *
 *
 * If the audience claim is explicitly configured as an optional claim and the list of accepted audience is non-empty, the following rules apply:
 *
 *  * If the audience claim is present (non-empty) in the JWT, it will be matched against the list of accepted audiences.
 *  * If the audience claim is not present, the audience match and existence checks are skipped - since it is an optional claim.
 *
 *
 *
 * An *empty* list of accepted audiences alone does *not* remove the audience ("aud") claim from the default set of required claims; the claim must explicitly be specified as optional.
 */
class DefaultConfigurableJwtValidator(issuer : String, acceptedAudiences : List<String>, optionalClaims : List<String>, val jwkSource : JWKSource<SecurityContext>) : JwtTokenValidator {

    private val jwtProcessor = DefaultJWTProcessor<SecurityContext>().apply {
        jwsKeySelector = JWSVerificationKeySelector(RS256, jwkSource)
        setJWTClaimsSetVerifier(DefaultJwtClaimsVerifier(acceptedAudiences(acceptedAudiences, optionalClaims),
            Builder().issuer(issuer).build(), difference(DEFAULT_REQUIRED_CLAIMS, optionalClaims),
            PROHIBITED_CLAIMS))
    }

    override fun assertValidToken(tokenString : String) {
        runCatching {
            jwtProcessor.process(tokenString, null)
        }.getOrElse {
            throw JwtTokenValidatorException("Token validation failed: ${it.message}", cause =  it)
        }
    }

    companion object {

        private val DEFAULT_REQUIRED_CLAIMS  = listOf(AUDIENCE, EXPIRATION_TIME, ISSUED_AT, ISSUER, SUBJECT)
        private val PROHIBITED_CLAIMS = emptySet<String>()
        private fun acceptedAudiences(acceptedAudiences: List<String>, optionalClaims: List<String>) =
             when {
                AUDIENCE !in optionalClaims -> acceptedAudiences.toSet()
                acceptedAudiences.isEmpty() ->  null
                else -> acceptedAudiences.plus(null as String?).toSet()
            }

        private fun <T> difference(first: List<T>, second: List<T>) = first.asSequence().filterNot { it in second }.toSet()
    }
}