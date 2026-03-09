package com.aandiclub.auth.admin.web

import com.aandiclub.auth.admin.service.AdminService
import com.aandiclub.auth.admin.web.dto.InviteMailResponse
import com.aandiclub.auth.admin.web.dto.InviteMailTarget
import com.aandiclub.auth.common.error.AppException
import com.aandiclub.auth.common.error.ErrorCode
import com.aandiclub.auth.common.error.GlobalExceptionHandler
import com.aandiclub.auth.user.domain.UserRole
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean
import reactor.core.publisher.Mono
import java.time.Instant

class AdminControllerTest : FunSpec({
	val testEmail = "new_member@aandi.club"
	val testEmail1 = "new_member_1@aandi.club"
	val testEmail2 = "new_member_2@aandi.club"

	val adminService = mockk<AdminService>(relaxed = true)
	val validator = LocalValidatorFactoryBean().apply { afterPropertiesSet() }
	val webTestClient = WebTestClient.bindToController(AdminController(adminService))
		.controllerAdvice(GlobalExceptionHandler())
		.validator(validator)
		.build()

	beforeTest {
		io.mockk.clearMocks(adminService)
	}

	test("POST /v1/admin/invite-mail returns invite payload") {
		every { adminService.sendInviteMail(any()) } returns Mono.just(
			InviteMailResponse(
				sentCount = 1,
				invites = listOf(
					InviteMailTarget(
						email = testEmail,
						username = "user_01",
						role = UserRole.USER,
						inviteExpiresAt = Instant.parse("2026-03-06T00:00:00Z"),
					),
				),
				username = "user_01",
				role = UserRole.USER,
				inviteExpiresAt = Instant.parse("2026-03-06T00:00:00Z"),
			),
		)

		webTestClient.post()
			.uri("/v1/admin/invite-mail")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(
				"""
				{
					"emails": [
						"$testEmail"
					],
					"role": "USER"
				}
				""".trimIndent()
			)
			.exchange()
			.expectStatus().isOk
			.expectBody()
			.jsonPath("$.success").isEqualTo(true)
			.jsonPath("$.data.sentCount").isEqualTo(1)
			.jsonPath("$.data.username").isEqualTo("user_01")
			.jsonPath("$.data.role").isEqualTo("USER")
	}

	test("POST /v1/admin/invite-mail accepts multiple emails") {
		val requestSlot = slot<com.aandiclub.auth.admin.web.dto.InviteMailRequest>()
		every { adminService.sendInviteMail(capture(requestSlot)) } returns Mono.just(
			InviteMailResponse(
				sentCount = 2,
				invites = listOf(
					InviteMailTarget(
						email = testEmail1,
						username = "user_02",
						role = UserRole.USER,
						inviteExpiresAt = Instant.parse("2026-03-06T00:00:00Z"),
					),
					InviteMailTarget(
						email = testEmail2,
						username = "user_03",
						role = UserRole.USER,
						inviteExpiresAt = Instant.parse("2026-03-06T00:00:00Z"),
					),
				),
			),
		)

		webTestClient.post()
			.uri("/v1/admin/invite-mail")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(
				"""
				{
					"emails": [
						"$testEmail1",
						"$testEmail2"
					],
					"role": "USER"
				}
				""".trimIndent()
			)
			.exchange()
			.expectStatus().isOk
			.expectBody()
			.jsonPath("$.success").isEqualTo(true)
			.jsonPath("$.data.sentCount").isEqualTo(2)
			.jsonPath("$.data.invites.length()").isEqualTo(2)

		requestSlot.captured.emails.size shouldBe 2
	}

	test("POST /v1/admin/invite-mail with invalid email returns bad request") {
		every { adminService.sendInviteMail(any()) } returns Mono.error(
			AppException(ErrorCode.INVALID_REQUEST, "invalid email format")
		)

		webTestClient.post()
			.uri("/v1/admin/invite-mail")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(
				"""
				{
					"emails": [
						"invalid-email"
					],
					"role": "USER"
				}
				""".trimIndent()
			)
			.exchange()
			.expectStatus().isBadRequest
			.expectBody()
			.jsonPath("$.success").isEqualTo(false)
			.jsonPath("$.error.code").isEqualTo("INVALID_REQUEST")
	}

	test("POST /v1/admin/invite-mail with empty emails array returns bad request") {
		webTestClient.post()
			.uri("/v1/admin/invite-mail")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(
				"""
				{
					"emails": [],
					"role": "USER"
				}
				""".trimIndent()
			)
			.exchange()
			.expectStatus().isBadRequest
			.expectBody()
			.jsonPath("$.success").isEqualTo(false)
			.jsonPath("$.error.code").isEqualTo("INVALID_REQUEST")
	}

	test("POST /v1/admin/invite-mail with missing emails field returns bad request") {
		webTestClient.post()
			.uri("/v1/admin/invite-mail")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(
				"""
				{
					"role": "USER"
				}
				""".trimIndent()
			)
			.exchange()
			.expectStatus().isBadRequest
			.expectBody()
			.jsonPath("$.success").isEqualTo(false)
			.jsonPath("$.error.code").isEqualTo("INVALID_REQUEST")
	}
})
