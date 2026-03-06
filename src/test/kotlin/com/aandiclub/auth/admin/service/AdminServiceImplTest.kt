package com.aandiclub.auth.admin.service

import com.aandiclub.auth.admin.config.InviteProperties
import com.aandiclub.auth.admin.domain.UserInviteEntity
import com.aandiclub.auth.admin.invite.InviteTokenCacheService
import com.aandiclub.auth.admin.password.CredentialGenerator
import com.aandiclub.auth.admin.repository.UserInviteRepository
import com.aandiclub.auth.admin.service.InviteMailService
import com.aandiclub.auth.admin.sequence.UsernameSequenceService
import com.aandiclub.auth.admin.service.impl.AdminServiceImpl
import com.aandiclub.auth.admin.web.dto.CreateAdminUserRequest
import com.aandiclub.auth.admin.web.dto.InviteMailRequest
import com.aandiclub.auth.admin.web.dto.ProvisionType
import com.aandiclub.auth.common.error.AppException
import com.aandiclub.auth.common.error.ErrorCode
import com.aandiclub.auth.security.service.PasswordService
import com.aandiclub.auth.security.token.TokenHashService
import com.aandiclub.auth.user.domain.UserEntity
import com.aandiclub.auth.user.domain.UserRole
import com.aandiclub.auth.user.repository.UserRepository
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import reactor.test.StepVerifier
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID

class AdminServiceImplTest : FunSpec({
	val userRepository = mockk<UserRepository>()
	val userInviteRepository = mockk<UserInviteRepository>()
	val inviteTokenCacheService = mockk<InviteTokenCacheService>()
	val usernameSequenceService = mockk<UsernameSequenceService>()
	val credentialGenerator = mockk<CredentialGenerator>()
	val passwordService = mockk<PasswordService>()
	val tokenHashService = mockk<TokenHashService>()
	val inviteMailService = mockk<InviteMailService>()
	val clock = Clock.fixed(Instant.parse("2026-02-18T00:00:00Z"), ZoneOffset.UTC)

	val service = AdminServiceImpl(
		userRepository = userRepository,
		userInviteRepository = userInviteRepository,
		inviteTokenCacheService = inviteTokenCacheService,
		usernameSequenceService = usernameSequenceService,
		credentialGenerator = credentialGenerator,
		passwordService = passwordService,
		tokenHashService = tokenHashService,
		inviteProperties = InviteProperties(
			activationBaseUrl = "https://your-domain.com/activate",
			expirationHours = 72,
		),
		inviteMailService = inviteMailService,
		clock = clock,
	)

	test("createUser PASSWORD should generate temporary password") {
		val savedUser = UserEntity(
			id = UUID.randomUUID(),
			username = "user_01",
			passwordHash = "hashed-password",
			role = UserRole.USER,
			forcePasswordChange = true,
		)
		val savedEntitySlot = slot<UserEntity>()

		every { usernameSequenceService.nextSequence() } returns Mono.just(1)
		every { credentialGenerator.randomPassword(32) } returns "A".repeat(32)
		every { passwordService.hash("A".repeat(32)) } returns "hashed-password"
		every { userRepository.save(capture(savedEntitySlot)) } returns Mono.just(savedUser)

		StepVerifier.create(
			service.createUser(
				CreateAdminUserRequest(role = UserRole.USER, provisionType = ProvisionType.PASSWORD),
			),
		)
			.assertNext { response ->
				response.username shouldBe "user_01"
				response.temporaryPassword shouldBe "A".repeat(32)
				response.role shouldBe UserRole.USER
				response.provisionType shouldBe ProvisionType.PASSWORD
			}
			.verifyComplete()

		savedEntitySlot.captured.username shouldBe "user_01"
		savedEntitySlot.captured.passwordHash shouldBe "hashed-password"
		savedEntitySlot.captured.forcePasswordChange shouldBe true
		savedEntitySlot.captured.userTrack shouldBe "NO"
		savedEntitySlot.captured.cohort shouldBe 0
		savedEntitySlot.captured.cohortOrder shouldBe 0
		savedEntitySlot.captured.publicCode shouldBe "user_01"
	}

	test("createUser INVITE should return one-time invite link and inactive account") {
		val userId = UUID.randomUUID()
		val savedUser = UserEntity(
			id = userId,
			username = "user_02",
			passwordHash = "placeholder-hash",
			role = UserRole.USER,
			forcePasswordChange = true,
			isActive = false,
		)
		val savedUserSlot = slot<UserEntity>()
		val inviteSlot = slot<UserInviteEntity>()

		every { usernameSequenceService.nextSequence() } returns Mono.just(2)
		every { credentialGenerator.randomToken(any()) } returns "invite-token"
		every { tokenHashService.sha256Hex("invite-token") } returns "invite-hash"
		every { credentialGenerator.randomPassword(32) } returns "B".repeat(32)
		every { passwordService.hash("B".repeat(32)) } returns "placeholder-hash"
		every { userRepository.save(capture(savedUserSlot)) } returns Mono.just(savedUser)
		every { userInviteRepository.save(capture(inviteSlot)) } answers { Mono.just(firstArg()) }
		every { inviteTokenCacheService.cacheToken("invite-hash", "invite-token", any()) } returns Mono.just(true)

		StepVerifier.create(
			service.createUser(
				CreateAdminUserRequest(role = UserRole.USER, provisionType = ProvisionType.INVITE),
			),
		).assertNext { response ->
			response.username shouldBe "user_02"
			response.provisionType shouldBe ProvisionType.INVITE
			response.inviteLink shouldBe "https://your-domain.com/activate?token=invite-token"
			response.temporaryPassword shouldBe null
		}.verifyComplete()

		savedUserSlot.captured.isActive shouldBe false
		savedUserSlot.captured.forcePasswordChange shouldBe true
		savedUserSlot.captured.userTrack shouldBe "NO"
		savedUserSlot.captured.cohort shouldBe 0
		savedUserSlot.captured.cohortOrder shouldBe 0
		savedUserSlot.captured.publicCode shouldBe "user_02"
		inviteSlot.captured.userId shouldBe userId
		inviteSlot.captured.tokenHash shouldBe "invite-hash"
	}

	test("resetPassword should set forcePasswordChange and return temporary password") {
		val userId = UUID.randomUUID()
		val user = UserEntity(
			id = userId,
			username = "user_03",
			passwordHash = "old",
			role = UserRole.USER,
		)
		val savedSlot = slot<UserEntity>()

		every { userRepository.findById(userId) } returns Mono.just(user)
		every { credentialGenerator.randomPassword(32) } returns "C".repeat(32)
		every { passwordService.hash("C".repeat(32)) } returns "new-hash"
		every { userRepository.save(capture(savedSlot)) } returns Mono.just(user.copy(passwordHash = "new-hash", forcePasswordChange = true))

		StepVerifier.create(service.resetPassword(userId))
			.assertNext { response ->
				response.temporaryPassword shouldBe "C".repeat(32)
			}
			.verifyComplete()

		savedSlot.captured.forcePasswordChange shouldBe true
	}

	test("getUsers should include inviteLink for inactive user with valid invite") {
		val userId = UUID.randomUUID()
		val now = Instant.parse("2026-02-18T00:00:00Z")
		val invite = UserInviteEntity(
			id = UUID.randomUUID(),
			userId = userId,
			tokenHash = "invite-hash",
			expiresAt = now.plusSeconds(3600),
			usedAt = null,
			createdAt = now,
		)
		every { userRepository.findAll() } returns Flux.just(
			UserEntity(
				id = userId,
				username = "user_10",
				passwordHash = "h1",
				role = UserRole.USER,
				isActive = false,
				forcePasswordChange = true,
			),
		)
		every {
			userInviteRepository.findByUserIdOrderByCreatedAtDesc(userId)
		} returns Flux.just(invite)
		every { inviteTokenCacheService.findToken("invite-hash") } returns Mono.just("raw-token")

		StepVerifier.create(service.getUsers())
			.assertNext { users ->
				users.size shouldBe 1
				users[0].inviteLink shouldBe "https://your-domain.com/activate?token=raw-token"
			}
			.verifyComplete()
	}

	test("getUsers should return summarized users") {
		every { userRepository.findAll() } returns Flux.just(
			UserEntity(
				id = UUID.randomUUID(),
				username = "user_01",
				passwordHash = "h1",
				role = UserRole.USER,
				isActive = true,
				forcePasswordChange = false,
			),
			UserEntity(
				id = UUID.randomUUID(),
				username = "admin",
				passwordHash = "h2",
				role = UserRole.ADMIN,
				isActive = true,
				forcePasswordChange = false,
			),
		)
		every {
			userInviteRepository.findByUserIdOrderByCreatedAtDesc(any())
		} returns Flux.empty()

		StepVerifier.create(service.getUsers())
			.assertNext { users ->
				users.size shouldBe 2
				users[0].username shouldBe "user_01"
				users[1].role shouldBe UserRole.ADMIN
			}
				.verifyComplete()
	}

	test("sendInviteMail should create invite user and send invite email") {
		val userId = UUID.randomUUID()
		val savedUser = UserEntity(
			id = userId,
			username = "user_03",
			passwordHash = "placeholder-hash",
			role = UserRole.USER,
			forcePasswordChange = true,
			isActive = false,
		)
		val inviteSlot = slot<UserInviteEntity>()
		val savedUserSlot = slot<UserEntity>()

		every { usernameSequenceService.nextSequence() } returns Mono.just(3)
		every { credentialGenerator.randomToken(any()) } returns "invite-mail-token"
		every { tokenHashService.sha256Hex("invite-mail-token") } returns "invite-mail-hash"
		every { credentialGenerator.randomPassword(32) } returns "D".repeat(32)
		every { passwordService.hash("D".repeat(32)) } returns "placeholder-hash"
		every { userRepository.save(capture(savedUserSlot)) } returns Mono.just(savedUser)
		every { userInviteRepository.save(capture(inviteSlot)) } answers { Mono.just(firstArg()) }
		every { inviteTokenCacheService.cacheToken("invite-mail-hash", "invite-mail-token", any()) } returns Mono.just(true)
			every {
				inviteMailService.sendInviteMail(
					toEmail = "new_member@aandi.club",
					username = "user_03",
					role = UserRole.USER,
					inviteUrl = "https://your-domain.com/activate?token=invite-mail-token",
					expiresAt = any(),
					userTrack = "NO",
					cohort = 0,
					cohortOrder = 0,
					publicCode = "user_03",
				)
			} returns Mono.empty()

		StepVerifier.create(service.sendInviteMail(InviteMailRequest(email = "new_member@aandi.club", role = UserRole.USER)))
			.assertNext { response ->
				response.sentCount shouldBe 1
				response.username shouldBe "user_03"
				response.role shouldBe UserRole.USER
				response.invites.size shouldBe 1
				response.invites[0].email shouldBe "new_member@aandi.club"
			}
			.verifyComplete()

		inviteSlot.captured.userId shouldBe userId
		savedUserSlot.captured.userTrack shouldBe "NO"
		savedUserSlot.captured.cohort shouldBe 0
		savedUserSlot.captured.cohortOrder shouldBe 0
		savedUserSlot.captured.publicCode shouldBe "user_03"
	}

	test("sendInviteMail should send to multiple emails and keep backward-compatible single fields null") {
		val savedUser1 = UserEntity(
			id = UUID.randomUUID(),
			username = "user_04",
			passwordHash = "placeholder-hash",
			role = UserRole.USER,
			forcePasswordChange = true,
			isActive = false,
		)
		val savedUser2 = UserEntity(
			id = UUID.randomUUID(),
			username = "user_05",
			passwordHash = "placeholder-hash",
			role = UserRole.USER,
			forcePasswordChange = true,
			isActive = false,
		)
		var sequence = 3L

		every { usernameSequenceService.nextSequence() } answers {
			sequence += 1L
			Mono.just(sequence)
		}
		every { credentialGenerator.randomToken(any()) } returnsMany listOf("invite-token-1", "invite-token-2")
		every { tokenHashService.sha256Hex("invite-token-1") } returns "invite-hash-1"
		every { tokenHashService.sha256Hex("invite-token-2") } returns "invite-hash-2"
		every { credentialGenerator.randomPassword(32) } returns "E".repeat(32)
		every { passwordService.hash("E".repeat(32)) } returns "placeholder-hash"
		every { userRepository.save(any()) } returnsMany listOf(Mono.just(savedUser1), Mono.just(savedUser2))
			every { userInviteRepository.save(any()) } answers { Mono.just(firstArg()) }
			every { inviteTokenCacheService.cacheToken(any(), any(), any()) } returns Mono.just(true)
			every { inviteMailService.sendInviteMail(any(), any(), any(), any(), any(), any(), any(), any(), any()) } returns Mono.empty()

		StepVerifier.create(
			service.sendInviteMail(
				InviteMailRequest(
					emails = listOf("new_member_1@aandi.club", "new_member_2@aandi.club"),
					role = UserRole.USER,
				),
			),
		)
			.assertNext { response ->
				response.sentCount shouldBe 2
				response.username shouldBe null
				response.role shouldBe null
				response.inviteExpiresAt shouldBe null
				response.invites.size shouldBe 2
				response.invites[0].email shouldBe "new_member_1@aandi.club"
				response.invites[1].email shouldBe "new_member_2@aandi.club"
			}
			.verifyComplete()
	}

	test("sendInviteMail should persist and return cohort and track when provided") {
		val savedUser = UserEntity(
			id = UUID.randomUUID(),
			username = "user_06",
			passwordHash = "placeholder-hash",
			role = UserRole.USER,
			forcePasswordChange = true,
			isActive = false,
			userTrack = "FL",
			cohort = 10,
			cohortOrder = 3,
			publicCode = "user_06",
		)
		val savedUserSlot = slot<UserEntity>()

		every { usernameSequenceService.nextSequence() } returns Mono.just(6)
		every { credentialGenerator.randomToken(any()) } returns "invite-token-6"
		every { tokenHashService.sha256Hex("invite-token-6") } returns "invite-hash-6"
		every { credentialGenerator.randomPassword(32) } returns "F".repeat(32)
		every { passwordService.hash("F".repeat(32)) } returns "placeholder-hash"
		every { userRepository.save(capture(savedUserSlot)) } returns Mono.just(savedUser)
		every { userInviteRepository.save(any()) } answers { Mono.just(firstArg()) }
		every { inviteTokenCacheService.cacheToken(any(), any(), any()) } returns Mono.just(true)
		every { inviteMailService.sendInviteMail(any(), any(), any(), any(), any(), any(), any(), any(), any()) } returns Mono.empty()

		StepVerifier.create(
			service.sendInviteMail(
				InviteMailRequest(
					email = "new_member@aandi.club",
					role = UserRole.USER,
					cohort = 10,
					cohortOrder = 3,
					userTrack = "fl",
				),
			),
		)
			.assertNext { response ->
				response.sentCount shouldBe 1
				response.cohort shouldBe 10
				response.cohortOrder shouldBe 3
				response.userTrack shouldBe "FL"
				response.publicCode shouldBe "user_06"
			}
			.verifyComplete()

		savedUserSlot.captured.cohort shouldBe 10
		savedUserSlot.captured.cohortOrder shouldBe 3
		savedUserSlot.captured.userTrack shouldBe "FL"
	}

	test("sendInviteMail should reject unsupported userTrack") {
		StepVerifier.create(
			service.sendInviteMail(
				InviteMailRequest(
					email = "new_member@aandi.club",
					role = UserRole.USER,
					userTrack = "XX",
				),
			),
		)
			.expectErrorSatisfies { ex ->
				(ex as AppException).errorCode shouldBe ErrorCode.INVALID_REQUEST
			}
			.verify()
	}

	test("sendInviteMail should reject request when no recipient emails are provided") {
		StepVerifier.create(service.sendInviteMail(InviteMailRequest(role = UserRole.USER)))
			.expectErrorSatisfies { ex ->
				(ex as AppException).errorCode shouldBe ErrorCode.INVALID_REQUEST
			}
			.verify()
	}

	test("deleteUser should delete target user and cleanup invite tokens") {
		val actorId = UUID.randomUUID()
		val targetId = UUID.randomUUID()
		val targetUser = UserEntity(
			id = targetId,
			username = "user_delete",
			passwordHash = "h1",
			role = UserRole.USER,
		)
		val invite = UserInviteEntity(
			id = UUID.randomUUID(),
			userId = targetId,
			tokenHash = "invite-hash-delete",
			expiresAt = Instant.parse("2026-02-20T00:00:00Z"),
			createdAt = Instant.parse("2026-02-18T00:00:00Z"),
		)

		every { userRepository.findById(targetId) } returns Mono.just(targetUser)
		every { userInviteRepository.findByUserIdOrderByCreatedAtDesc(targetId) } returns Flux.just(invite)
		every { inviteTokenCacheService.deleteToken("invite-hash-delete") } returns Mono.just(true)
		every { userRepository.deleteById(targetId) } returns Mono.empty()

		StepVerifier.create(service.deleteUser(targetId, actorId))
			.verifyComplete()

		verify(exactly = 1) { userRepository.deleteById(targetId) }
	}

	test("updateUserRole should update target user's role") {
		val actorId = UUID.randomUUID()
		val targetId = UUID.randomUUID()
		val originalUser = UserEntity(
			id = targetId,
			username = "member_01",
			passwordHash = "h1",
			role = UserRole.USER,
		)
		val savedSlot = slot<UserEntity>()

		every { userRepository.findById(targetId) } returns Mono.just(originalUser)
		every { userRepository.save(capture(savedSlot)) } returns Mono.just(originalUser.copy(role = UserRole.ORGANIZER))

		StepVerifier.create(service.updateUserRole(targetId, UserRole.ORGANIZER, actorId))
			.assertNext { response ->
				response.id shouldBe targetId
				response.username shouldBe "member_01"
				response.role shouldBe UserRole.ORGANIZER
			}
			.verifyComplete()

		savedSlot.captured.role shouldBe UserRole.ORGANIZER
	}

	test("updateUserRole should reject self role change") {
		val adminId = UUID.randomUUID()
		StepVerifier.create(service.updateUserRole(adminId, UserRole.USER, adminId))
			.expectErrorSatisfies { ex ->
				(ex as AppException).errorCode shouldBe ErrorCode.FORBIDDEN
			}
			.verify()
	}

	test("deleteUser should reject self deletion") {
		val adminId = UUID.randomUUID()
		StepVerifier.create(service.deleteUser(adminId, adminId))
			.expectErrorSatisfies { ex ->
				(ex as AppException).errorCode shouldBe ErrorCode.FORBIDDEN
			}
			.verify()
	}
})
