package com.aandiclub.auth.auth.service.impl

import com.aandiclub.auth.auth.service.AuthService
import com.aandiclub.auth.admin.invite.InviteTokenCacheService
import com.aandiclub.auth.admin.repository.UserInviteRepository
import com.aandiclub.auth.auth.web.dto.ActivateRequest
import com.aandiclub.auth.auth.web.dto.ActivateResponse
import com.aandiclub.auth.auth.web.dto.LoginRequest
import com.aandiclub.auth.auth.web.dto.LoginResponse
import com.aandiclub.auth.auth.web.dto.LoginUser
import com.aandiclub.auth.auth.web.dto.LogoutRequest
import com.aandiclub.auth.auth.web.dto.LogoutResponse
import com.aandiclub.auth.auth.web.dto.RefreshRequest
import com.aandiclub.auth.auth.web.dto.RefreshResponse
import com.aandiclub.auth.common.error.AppException
import com.aandiclub.auth.common.error.ErrorCode
import com.aandiclub.auth.security.jwt.JwtTokenType
import com.aandiclub.auth.security.observability.NoopSecurityTelemetry
import com.aandiclub.auth.security.observability.SecurityTelemetry
import com.aandiclub.auth.security.service.JwtService
import com.aandiclub.auth.security.service.PasswordService
import com.aandiclub.auth.security.token.RefreshTokenStateService
import com.aandiclub.auth.security.token.TokenHashService
import com.aandiclub.auth.user.domain.UserEntity
import com.aandiclub.auth.user.repository.UserRepository
import org.slf4j.LoggerFactory
import org.springframework.dao.DataIntegrityViolationException
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import java.time.Clock
import java.time.Duration
import java.util.Locale

@Service
class AuthServiceImpl(
	private val userRepository: UserRepository,
	private val userInviteRepository: UserInviteRepository,
	private val inviteTokenCacheService: InviteTokenCacheService,
	private val passwordService: PasswordService,
	private val jwtService: JwtService,
	private val tokenHashService: TokenHashService,
	private val refreshTokenStateService: RefreshTokenStateService,
	private val securityTelemetry: SecurityTelemetry = NoopSecurityTelemetry,
	private val clock: Clock = Clock.systemUTC(),
) : AuthService {
	override fun login(request: LoginRequest): Mono<LoginResponse> =
		userRepository.findByUsername(request.username)
			.switchIfEmpty(Mono.defer { invalidCredentials(request.username) })
			.flatMap { user ->
				if (!user.isActive || !passwordService.matches(request.password, user.passwordHash)) {
					invalidCredentials(request.username)
				} else {
					val accessToken = jwtService.issueAccessToken(requireNotNull(user.id), user.username, user.role)
					val refreshToken = jwtService.issueRefreshToken(requireNotNull(user.id), user.username, user.role)
					val now = clock.instant()
					userRepository.save(user.copy(lastLoginAt = now)).map {
						LoginResponse(
							accessToken = accessToken.value,
							refreshToken = refreshToken.value,
							expiresIn = Duration.between(clock.instant(), accessToken.expiresAt).seconds,
							tokenType = "Bearer",
							forcePasswordChange = user.forcePasswordChange,
							user = LoginUser(
								id = requireNotNull(user.id),
								username = user.username,
								role = user.role,
								publicCode = user.publicCode,
							),
						)
					}
				}
			}

	override fun refresh(request: RefreshRequest): Mono<RefreshResponse> {
		return Mono.defer {
			val principal = jwtService.verifyAndParse(request.refreshToken, JwtTokenType.REFRESH)
			refreshTokenStateService.rejectIfLoggedOut(request.refreshToken)
				.then(
					Mono.fromSupplier {
						val accessToken = jwtService.issueAccessToken(principal.userId, principal.username, principal.role)
						RefreshResponse(
							accessToken = accessToken.value,
							expiresIn = Duration.between(clock.instant(), accessToken.expiresAt).seconds,
						)
					},
				)
		}
	}

	override fun logout(request: LogoutRequest): Mono<LogoutResponse> {
		return Mono.defer {
			val principal = jwtService.verifyAndParse(request.refreshToken, JwtTokenType.REFRESH)
			refreshTokenStateService.markLoggedOut(request.refreshToken, principal.expiresAt)
				.thenReturn(LogoutResponse(success = true))
		}
	}

	override fun activate(request: ActivateRequest): Mono<ActivateResponse> {
		return Mono.defer {
			val tokenHash = tokenHashService.sha256Hex(request.token)
			userInviteRepository.findByTokenHash(tokenHash)
				.switchIfEmpty(invalidInviteToken())
				.flatMap { invite ->
					val now = clock.instant()
					if (invite.usedAt != null || !invite.expiresAt.isAfter(now)) {
						invalidInviteToken()
					} else {
						userRepository.findById(invite.userId)
							.switchIfEmpty(Mono.error(AppException(ErrorCode.NOT_FOUND, "User not found.")))
							.flatMap { user -> resolveActivateUsername(normalizeUsername(request.username), user) }
							.flatMap { activateUser ->
								val updatedUser = activateUser.user.copy(
									username = activateUser.username,
									passwordHash = passwordService.hash(request.password),
									forcePasswordChange = false,
									isActive = true,
								)
								userRepository.save(updatedUser)
									.onErrorMap(DataIntegrityViolationException::class.java) {
										AppException(ErrorCode.INVALID_REQUEST, USERNAME_UNAVAILABLE_MESSAGE)
									}
									.then(userInviteRepository.save(invite.copy(usedAt = now)))
									.then(inviteTokenCacheService.deleteToken(invite.tokenHash))
									.map {
										logger.warn(
											"security_audit event=invite_activated user_id={} username={}",
											updatedUser.id,
											updatedUser.username,
										)
										ActivateResponse(success = true)
									}
							}
					}
				}
		}
	}

	private fun resolveActivateUsername(requestedUsername: String?, user: UserEntity): Mono<ActivateUser> {
		if (requestedUsername == null || requestedUsername == user.username) {
			return Mono.just(ActivateUser(user, user.username))
		}

		return userRepository.findByUsername(requestedUsername)
			.flatMap<ActivateUser> { existing ->
				if (existing.id == user.id) {
					Mono.just(ActivateUser(user, requestedUsername))
				} else {
					usernameUnavailable()
				}
			}
			.switchIfEmpty(Mono.just(ActivateUser(user, requestedUsername)))
	}

	private fun normalizeUsername(username: String?): String? = username?.lowercase(Locale.ROOT)

	private fun invalidCredentials(username: String): Mono<Nothing> {
		securityTelemetry.loginFailed(username)
		return Mono.error(AppException(ErrorCode.UNAUTHORIZED, INVALID_CREDENTIALS_MESSAGE))
	}

	private fun invalidInviteToken(): Mono<Nothing> =
		Mono.error(AppException(ErrorCode.UNAUTHORIZED, INVALID_INVITE_TOKEN_MESSAGE))

	private fun usernameUnavailable(): Mono<Nothing> =
		Mono.error(AppException(ErrorCode.INVALID_REQUEST, USERNAME_UNAVAILABLE_MESSAGE))

	private data class ActivateUser(
		val user: UserEntity,
		val username: String,
	)

	companion object {
		private const val INVALID_CREDENTIALS_MESSAGE = "Invalid username or password."
		private const val INVALID_INVITE_TOKEN_MESSAGE = "Invalid or expired invite token."
		private const val USERNAME_UNAVAILABLE_MESSAGE = "Requested username is not available."
		private val logger = LoggerFactory.getLogger(AuthServiceImpl::class.java)
	}
}
