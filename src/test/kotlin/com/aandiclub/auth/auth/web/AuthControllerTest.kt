package com.aandiclub.auth.auth.web

import com.aandiclub.auth.auth.service.AuthService
import com.aandiclub.auth.auth.web.dto.LoginResponse
import com.aandiclub.auth.auth.web.dto.LoginUser
import com.aandiclub.auth.auth.web.dto.LogoutResponse
import com.aandiclub.auth.auth.web.dto.RefreshResponse
import com.aandiclub.auth.common.error.AppException
import com.aandiclub.auth.common.error.ErrorCode
import com.aandiclub.auth.common.error.GlobalExceptionHandler
import com.aandiclub.auth.user.domain.UserRole
import io.kotest.core.spec.style.FunSpec
import io.mockk.every
import io.mockk.mockk
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient
import reactor.core.publisher.Mono
import java.util.UUID

class AuthControllerTest : FunSpec({
	val authService = mockk<AuthService>()
	val webTestClient = WebTestClient.bindToController(AuthController(authService))
		.controllerAdvice(GlobalExceptionHandler())
		.build()

	test("POST /v1/auth/login returns token payload") {
		every { authService.login(any()) } returns Mono.just(
			LoginResponse(
				accessToken = "access",
				refreshToken = "refresh",
				expiresIn = 3600,
				tokenType = "Bearer",
				forcePasswordChange = false,
				user = LoginUser(UUID.randomUUID(), "user_01", UserRole.USER, "#NO001"),
			),
		)

		webTestClient.post()
			.uri("/v1/auth/login")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue("""{"username":"user_01","password":"password"}""")
			.exchange()
			.expectStatus().isOk
			.expectBody()
			.jsonPath("$.success").isEqualTo(true)
			.jsonPath("$.data.accessToken").isEqualTo("access")
			.jsonPath("$.data.refreshToken").isEqualTo("refresh")
	}

	test("POST /v1/auth/refresh returns unauthorized when blocked") {
		every { authService.refresh(any()) } returns Mono.error(
			AppException(ErrorCode.UNAUTHORIZED, "Refresh token is logged out."),
		)

		webTestClient.post()
			.uri("/v1/auth/refresh")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue("""{"refreshToken":"r1"}""")
			.exchange()
			.expectStatus().isUnauthorized
			.expectBody()
			.jsonPath("$.success").isEqualTo(false)
			.jsonPath("$.error.code").isEqualTo("UNAUTHORIZED")
	}

	test("POST /v1/auth/logout returns success") {
		every { authService.logout(any()) } returns Mono.just(LogoutResponse(success = true))

		webTestClient.post()
			.uri("/v1/auth/logout")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue("""{"refreshToken":"r1"}""")
			.exchange()
			.expectStatus().isOk
			.expectBody()
			.jsonPath("$.success").isEqualTo(true)
			.jsonPath("$.data.success").isEqualTo(true)
	}

	test("POST /v1/auth/refresh with malformed payload returns bad request") {
		every { authService.refresh(any()) } returns Mono.just(RefreshResponse("a", 3600))

		webTestClient.post()
			.uri("/v1/auth/refresh")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue("""{"refreshToken":}""")
			.exchange()
			.expectStatus().isBadRequest
			.expectBody()
			.jsonPath("$.success").isEqualTo(false)
			.jsonPath("$.error.code").isEqualTo("INVALID_REQUEST")
	}
})
