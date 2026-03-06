package com.aandiclub.auth.admin.service.impl

import com.aandiclub.auth.admin.config.InviteProperties
import com.aandiclub.auth.admin.domain.UserInviteEntity
import com.aandiclub.auth.admin.invite.InviteTokenCacheService
import com.aandiclub.auth.admin.password.CredentialGenerator
import com.aandiclub.auth.admin.repository.UserInviteRepository
import com.aandiclub.auth.admin.service.AdminService
import com.aandiclub.auth.admin.service.InviteMailService
import com.aandiclub.auth.admin.sequence.UsernameSequenceService
import com.aandiclub.auth.admin.web.dto.AdminUserSummary
import com.aandiclub.auth.admin.web.dto.CreateAdminUserRequest
import com.aandiclub.auth.admin.web.dto.CreateAdminUserResponse
import com.aandiclub.auth.admin.web.dto.InviteMailRequest
import com.aandiclub.auth.admin.web.dto.InviteMailResponse
import com.aandiclub.auth.admin.web.dto.InviteMailTarget
import com.aandiclub.auth.admin.web.dto.ProvisionType
import com.aandiclub.auth.admin.web.dto.ResetPasswordResponse
import com.aandiclub.auth.admin.web.dto.UpdateUserRoleResponse
import com.aandiclub.auth.common.error.AppException
import com.aandiclub.auth.common.error.ErrorCode
import com.aandiclub.auth.security.service.PasswordService
import com.aandiclub.auth.security.token.TokenHashService
import com.aandiclub.auth.user.domain.UserEntity
import com.aandiclub.auth.user.domain.UserRole
import com.aandiclub.auth.user.repository.UserRepository
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import java.time.Clock
import java.time.Duration
import java.util.UUID

@Service
class AdminServiceImpl(
	private val userRepository: UserRepository,
	private val userInviteRepository: UserInviteRepository,
	private val inviteTokenCacheService: InviteTokenCacheService,
	private val usernameSequenceService: UsernameSequenceService,
	private val credentialGenerator: CredentialGenerator,
	private val passwordService: PasswordService,
	private val tokenHashService: TokenHashService,
	private val inviteProperties: InviteProperties,
	private val inviteMailService: InviteMailService,
	private val clock: Clock = Clock.systemUTC(),
) : AdminService {
	override fun getUsers(): Mono<List<AdminUserSummary>> =
		userRepository.findAll()
			.flatMap { toAdminUserSummary(it, clock.instant()) }
			.collectList()

	override fun createUser(request: CreateAdminUserRequest): Mono<CreateAdminUserResponse> =
		Mono.fromCallable { resolveProvisioningProfile(request.userTrack, request.cohort, request.cohortOrder) }
			.flatMap { provisioningProfile ->
				usernameSequenceService.nextSequence()
			.flatMap { sequence ->
				val username = "user_${sequence.toString().padStart(2, '0')}"
				when (request.provisionType) {
					ProvisionType.PASSWORD -> createPasswordProvisionedUser(username, request, provisioningProfile)
					ProvisionType.INVITE -> createInviteProvisionedUser(username, request, provisioningProfile)
				}
			}
			}

	override fun resetPassword(userId: UUID): Mono<ResetPasswordResponse> =
		userRepository.findById(userId)
			.switchIfEmpty(Mono.error(AppException(ErrorCode.NOT_FOUND, "User not found.")))
			.flatMap { user ->
				val temporaryPassword = credentialGenerator.randomPassword(32)
				val hashedPassword = passwordService.hash(temporaryPassword)
				userRepository.save(
					user.copy(
						passwordHash = hashedPassword,
						forcePasswordChange = true,
					),
				).map {
					logger.warn("security_audit event=admin_password_reset user_id={} username={}", it.id, it.username)
					ResetPasswordResponse(temporaryPassword = temporaryPassword)
				}
			}

	override fun updateUserRole(targetUserId: UUID, role: UserRole, actorUserId: UUID): Mono<UpdateUserRoleResponse> {
		if (targetUserId == actorUserId) {
			return Mono.error(AppException(ErrorCode.FORBIDDEN, "Admin cannot change own role."))
		}

		return userRepository.findById(targetUserId)
			.switchIfEmpty(Mono.error(AppException(ErrorCode.NOT_FOUND, "User not found.")))
			.flatMap { user ->
				userRepository.save(user.copy(role = role))
					.map { saved ->
						logger.warn(
							"security_audit event=admin_user_role_changed user_id={} username={} old_role={} new_role={}",
							saved.id,
							saved.username,
							user.role,
							saved.role,
						)
						UpdateUserRoleResponse(
							id = requireNotNull(saved.id),
							username = saved.username,
							role = saved.role,
						)
					}
			}
	}

	override fun deleteUser(targetUserId: UUID, actorUserId: UUID): Mono<Void> {
		if (targetUserId == actorUserId) {
			return Mono.error(AppException(ErrorCode.FORBIDDEN, "Admin cannot delete own account."))
		}

		return userRepository.findById(targetUserId)
			.switchIfEmpty(Mono.error(AppException(ErrorCode.NOT_FOUND, "User not found.")))
			.flatMap { user ->
				userInviteRepository.findByUserIdOrderByCreatedAtDesc(requireNotNull(user.id))
					.concatMap { inviteTokenCacheService.deleteToken(it.tokenHash) }
					.then(userRepository.deleteById(requireNotNull(user.id)))
					.then(
						Mono.fromRunnable {
							logger.warn("security_audit event=admin_user_deleted user_id={} username={}", user.id, user.username)
						},
					)
					.then()
				}
	}

	override fun sendInviteMail(request: InviteMailRequest): Mono<InviteMailResponse> =
		Mono.defer {
			val recipientEmails = request.recipientEmails()
			if (recipientEmails.isEmpty()) {
				return@defer Mono.error(AppException(ErrorCode.INVALID_REQUEST, "At least one email is required."))
			}
			val provisioningProfile = resolveProvisioningProfile(request.userTrack, request.cohort, request.cohortOrder)

			Flux.fromIterable(recipientEmails)
				.concatMap { recipientEmail ->
					usernameSequenceService.nextSequence()
						.flatMap { sequence ->
							val username = "user_${sequence.toString().padStart(2, '0')}"
							createInviteProvisionedUser(
								username = username,
								request = CreateAdminUserRequest(
									role = request.role,
									provisionType = ProvisionType.INVITE,
								),
								provisioningProfile = provisioningProfile,
							).flatMap { created ->
								val inviteLink = created.inviteLink
									?: return@flatMap Mono.error(
										AppException(ErrorCode.INTERNAL_SERVER_ERROR, "Failed to issue invite link."),
									)
								val expiresAt = created.expiresAt
									?: return@flatMap Mono.error(
										AppException(ErrorCode.INTERNAL_SERVER_ERROR, "Failed to issue invite expiration."),
									)
								inviteMailService
									.sendInviteMail(
										toEmail = recipientEmail,
										username = created.username,
										role = created.role,
										inviteUrl = inviteLink,
										expiresAt = expiresAt,
										userTrack = created.userTrack,
										cohort = created.cohort,
										cohortOrder = created.cohortOrder,
										publicCode = created.publicCode,
									)
									.thenReturn(
										InviteMailTarget(
											email = recipientEmail,
											username = created.username,
											role = created.role,
											inviteExpiresAt = expiresAt,
											userTrack = created.userTrack,
											cohort = created.cohort,
											cohortOrder = created.cohortOrder,
											publicCode = created.publicCode,
										),
									)
							}
						}
				}
				.collectList()
				.map { invites ->
					val singleInvite = invites.singleOrNull()
					InviteMailResponse(
						sentCount = invites.size,
						invites = invites,
						username = singleInvite?.username,
						role = singleInvite?.role,
						inviteExpiresAt = singleInvite?.inviteExpiresAt,
						cohort = singleInvite?.cohort,
						cohortOrder = singleInvite?.cohortOrder,
						userTrack = singleInvite?.userTrack,
						publicCode = singleInvite?.publicCode,
					)
				}
		}

	private fun createPasswordProvisionedUser(
		username: String,
		request: CreateAdminUserRequest,
		provisioningProfile: ProvisioningProfile,
	): Mono<CreateAdminUserResponse> {
		val temporaryPassword = credentialGenerator.randomPassword(32)
		val hashedPassword = passwordService.hash(temporaryPassword)
		return userRepository.save(
			UserEntity(
				username = username,
				passwordHash = hashedPassword,
				role = request.role,
				forcePasswordChange = true,
				isActive = true,
				userTrack = provisioningProfile.userTrack,
				cohort = provisioningProfile.cohort,
				cohortOrder = provisioningProfile.cohortOrder,
			),
		).map { saved ->
			logger.warn("security_audit event=admin_user_created type=password user_id={} username={} role={}", saved.id, saved.username, saved.role)
			CreateAdminUserResponse(
				id = requireNotNull(saved.id),
				username = saved.username,
				role = saved.role,
				provisionType = ProvisionType.PASSWORD,
				temporaryPassword = temporaryPassword,
				userTrack = saved.userTrack,
				cohort = saved.cohort,
				cohortOrder = saved.cohortOrder,
				publicCode = saved.publicCode,
			)
		}
	}

	private fun createInviteProvisionedUser(
		username: String,
		request: CreateAdminUserRequest,
		provisioningProfile: ProvisioningProfile,
	): Mono<CreateAdminUserResponse> {
		val rawInviteToken = credentialGenerator.randomToken()
		val hashedInviteToken = tokenHashService.sha256Hex(rawInviteToken)
		val placeholderPasswordHash = passwordService.hash(credentialGenerator.randomPassword(32))
		val now = clock.instant()
		val expiresAt = now.plus(Duration.ofHours(inviteProperties.expirationHours))
		return userRepository.save(
			UserEntity(
				username = username,
				passwordHash = placeholderPasswordHash,
				role = request.role,
				forcePasswordChange = true,
				isActive = false,
				userTrack = provisioningProfile.userTrack,
				cohort = provisioningProfile.cohort,
				cohortOrder = provisioningProfile.cohortOrder,
			),
		).flatMap { savedUser ->
			userInviteRepository.save(
				UserInviteEntity(
					userId = requireNotNull(savedUser.id),
					tokenHash = hashedInviteToken,
					expiresAt = expiresAt,
					createdAt = now,
				),
			).flatMap { savedInvite ->
				inviteTokenCacheService.cacheToken(savedInvite.tokenHash, rawInviteToken, expiresAt)
					.thenReturn(savedInvite)
			}.map {
				logger.warn(
					"security_audit event=admin_user_created type=invite user_id={} username={} role={} expires_at={}",
					savedUser.id,
					savedUser.username,
					savedUser.role,
					expiresAt,
				)
				CreateAdminUserResponse(
					id = requireNotNull(savedUser.id),
					username = savedUser.username,
					role = savedUser.role,
					provisionType = ProvisionType.INVITE,
					inviteLink = "${inviteProperties.activationBaseUrl}?token=$rawInviteToken",
					expiresAt = expiresAt,
					userTrack = savedUser.userTrack,
					cohort = savedUser.cohort,
					cohortOrder = savedUser.cohortOrder,
					publicCode = savedUser.publicCode,
				)
			}
		}
	}

	private fun resolveProvisioningProfile(
		rawUserTrack: String?,
		rawCohort: Int?,
		rawCohortOrder: Int?,
	): ProvisioningProfile {
		val userTrack = rawUserTrack?.trim()?.uppercase()
			?.takeIf { it.isNotEmpty() }
			?: DEFAULT_USER_TRACK
		if (userTrack !in ALLOWED_USER_TRACKS) {
			throw AppException(
				ErrorCode.INVALID_REQUEST,
				"userTrack must be one of ${ALLOWED_USER_TRACKS.joinToString(", ")}.",
			)
		}

		val cohort = rawCohort ?: 0
		if (cohort < 0) {
			throw AppException(ErrorCode.INVALID_REQUEST, "cohort must be greater than or equal to 0.")
		}

		val cohortOrder = rawCohortOrder ?: 0
		if (cohortOrder < 0) {
			throw AppException(ErrorCode.INVALID_REQUEST, "cohortOrder must be greater than or equal to 0.")
		}

		return ProvisioningProfile(
			userTrack = userTrack,
			cohort = cohort,
			cohortOrder = cohortOrder,
		)
	}

	private data class ProvisioningProfile(
		val userTrack: String,
		val cohort: Int,
		val cohortOrder: Int,
	)

	private fun toAdminUserSummary(user: UserEntity, now: java.time.Instant): Mono<AdminUserSummary> {
		val baseSummary = AdminUserSummary(
			id = requireNotNull(user.id),
			username = user.username,
			role = user.role,
			isActive = user.isActive,
			forcePasswordChange = user.forcePasswordChange,
		)
		if (user.isActive) {
			return Mono.just(baseSummary)
		}

		return userInviteRepository
			.findByUserIdOrderByCreatedAtDesc(requireNotNull(user.id))
			.filter { it.usedAt == null && it.expiresAt.isAfter(now) }
			.next()
			.flatMap { invite ->
				inviteTokenCacheService.findToken(invite.tokenHash)
					.map { token ->
						baseSummary.copy(
							inviteLink = "${inviteProperties.activationBaseUrl}?token=$token",
							inviteExpiresAt = invite.expiresAt,
						)
					}
					.defaultIfEmpty(baseSummary.copy(inviteExpiresAt = invite.expiresAt))
			}
			.switchIfEmpty(Mono.just(baseSummary))
	}

	companion object {
		private val logger = LoggerFactory.getLogger(AdminServiceImpl::class.java)
		private const val DEFAULT_USER_TRACK = "NO"
		private val ALLOWED_USER_TRACKS = setOf("NO", "FL", "SP")
	}
}
