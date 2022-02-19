package no.nav.security.token.support.spring.validation.interceptor

import org.springframework.http.HttpStatus.UNAUTHORIZED
import org.springframework.web.bind.annotation.ResponseStatus
import java.lang.RuntimeException

@ResponseStatus(UNAUTHORIZED)
class JwtTokenUnauthorizedException(cause: Throwable): RuntimeException(cause)