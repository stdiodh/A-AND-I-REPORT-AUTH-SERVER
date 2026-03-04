package com.aandiclub.auth.admin.web

import com.aandiclub.auth.admin.service.AdminService
import com.aandiclub.auth.admin.web.dto.InviteMailResponse
import com.aandiclub.auth.admin.web.dto.InviteMailTarget
import com.aandiclub.auth.common.error.GlobalExceptionHandler
import com.aandiclub.auth.user.domain.UserRole
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient
import reactor.core.publisher.Mono
import java.time.Instant

class AdminControllerTest : FunSpec({
	val adminService = mockk<AdminService>(relaxed = true)
	val webTestClient = WebTestClient.bindToController(AdminController(adminService))
		.controllerAdvice(GlobalExceptionHandler())
		.build()

	test("POST /v1/admin/invite-mail returns invite payload") {
		every { adminService.sendInviteMail(any()) } returns Mono.just(
			InviteMailResponse(
				sentCount = 1,
				invites = listOf(
					InviteMailTarget(
						email = "new_member@aandi.club",
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
			.bodyValue("""{"email":"new_member@aandi.club","role":"USER"}""")
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
						email = "new_member_1@aandi.club",
						username = "user_02",
						role = UserRole.USER,
						inviteExpiresAt = Instant.parse("2026-03-06T00:00:00Z"),
					),
					InviteMailTarget(
						email = "new_member_2@aandi.club",
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
			.bodyValue("""{"emails":["new_member_1@aandi.club","new_member_2@aandi.club"],"role":"USER"}""")
			.exchange()
			.expectStatus().isOk
			.expectBody()
			.jsonPath("$.success").isEqualTo(true)
			.jsonPath("$.data.sentCount").isEqualTo(2)
			.jsonPath("$.data.invites.length()").isEqualTo(2)

		requestSlot.captured.emails.size shouldBe 2
	}

	test("POST /v1/admin/invite-mail with invalid email returns bad request") {
		webTestClient.post()
			.uri("/v1/admin/invite-mail")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue("""{"email":"invalid-email","role":"USER"}""")
			.exchange()
			.expectStatus().isBadRequest
			.expectBody()
			.jsonPath("$.success").isEqualTo(false)
			.jsonPath("$.error.code").isEqualTo("INVALID_REQUEST")
	}
})
