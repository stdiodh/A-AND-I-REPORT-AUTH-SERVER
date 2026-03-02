package com.aandiclub.auth.user.service.impl

import com.aandiclub.auth.security.auth.AuthenticatedUser
import com.aandiclub.auth.security.service.PasswordService
import com.aandiclub.auth.common.error.AppException
import com.aandiclub.auth.common.error.ErrorCode
import com.aandiclub.auth.user.config.ProfileImageProperties
import com.aandiclub.auth.user.config.ProfileProperties
import com.aandiclub.auth.user.domain.UserEntity
import com.aandiclub.auth.user.domain.UserRole
import com.aandiclub.auth.user.event.UserProfileEventPublisher
import com.aandiclub.auth.user.event.UserProfileUpdatedEvent
import com.aandiclub.auth.user.repository.UserRepository
import com.aandiclub.auth.user.service.UserPublicCodeService
import com.aandiclub.auth.user.service.UserService
import com.aandiclub.auth.user.web.dto.ChangePasswordRequest
import com.aandiclub.auth.user.web.dto.ChangePasswordResponse
import com.aandiclub.auth.user.web.dto.CreateProfileImageUploadUrlRequest
import com.aandiclub.auth.user.web.dto.CreateProfileImageUploadUrlResponse
import com.aandiclub.auth.user.web.dto.MeResponse
import com.aandiclub.auth.user.web.dto.UserLookupResponse
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.http.codec.multipart.FilePart
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers
import java.net.URI
import java.time.Duration
import java.util.UUID
import java.nio.file.Files
import java.nio.file.Path
import software.amazon.awssdk.services.s3.model.PutObjectRequest
import software.amazon.awssdk.services.s3.S3Client
import software.amazon.awssdk.services.s3.presigner.S3Presigner
import software.amazon.awssdk.services.s3.presigner.model.PutObjectPresignRequest
import software.amazon.awssdk.core.sync.RequestBody

@Service
class UserServiceImpl(
	private val userRepository: UserRepository,
	private val passwordService: PasswordService,
	private val userPublicCodeService: UserPublicCodeService,
	private val userProfileEventPublisher: UserProfileEventPublisher,
	private val profileImageProperties: ProfileImageProperties,
	private val s3Presigner: S3Presigner,
	private val s3Client: S3Client,
	profileProperties: ProfileProperties,
) : UserService {
	private val allowedImageHosts = profileProperties.allowedImageHostsSet()

	override fun getMe(user: AuthenticatedUser): Mono<MeResponse> =
		userRepository.findById(user.userId)
			.switchIfEmpty(Mono.error(AppException(ErrorCode.NOT_FOUND, "User not found.")))
			.map { toMeResponse(it) }

	override fun lookupByPublicCode(code: String): Mono<UserLookupResponse> {
		val normalizedCode = userPublicCodeService.normalizeLookupCode(code)
		return userRepository.findByPublicCode(normalizedCode)
			.filter { it.role != UserRole.ADMIN }
			.switchIfEmpty(Mono.error(AppException(ErrorCode.NOT_FOUND, "User not found.")))
			.map { entity ->
				UserLookupResponse(
					id = requireNotNull(entity.id),
					username = entity.username,
					role = entity.role,
					publicCode = entity.publicCode,
					nickname = entity.nickname,
					profileImageUrl = entity.profileImageUrl,
				)
			}
	}

	override fun updateProfile(
		user: AuthenticatedUser,
		nickname: String?,
		profileImage: FilePart?,
		profileImageUrl: String?,
	): Mono<MeResponse> {
		if (profileImage != null && profileImageUrl != null) {
			return Mono.error(AppException(ErrorCode.INVALID_REQUEST, "profileImage and profileImageUrl cannot be used together."))
		}
		if (nickname == null && profileImage == null && profileImageUrl == null) {
			return Mono.error(AppException(ErrorCode.INVALID_REQUEST, "At least one profile field is required."))
		}
		val normalizedNickname = try {
			nickname?.let { normalizeNickname(it) }
		} catch (ex: AppException) {
			return Mono.error(ex)
		}
		val normalizedProfileImageUrl = try {
			profileImageUrl?.let { normalizeProfileImageUrl(it) }
		} catch (ex: AppException) {
			return Mono.error(ex)
		}

		return userRepository.findById(user.userId)
			.switchIfEmpty(Mono.error(AppException(ErrorCode.NOT_FOUND, "User not found.")))
			.flatMap { entity ->
				val uploadMono = when {
					profileImage != null -> uploadProfileImage(user.userId, profileImage)
					normalizedProfileImageUrl != null -> Mono.just(normalizedProfileImageUrl)
					else -> Mono.empty<String>()
				}
				uploadMono.defaultIfEmpty(entity.profileImageUrl ?: "")
					.flatMap { uploadedProfileImageUrl ->
						userRepository.save(
							entity.copy(
								nickname = normalizedNickname ?: entity.nickname,
								profileImageUrl = if (uploadedProfileImageUrl.isBlank()) null else uploadedProfileImageUrl,
								profileVersion = entity.profileVersion + 1,
							),
						).flatMap { updated ->
							logger.warn("security_audit event=profile_updated user_id={}", updated.id)
							userProfileEventPublisher.publishUserProfileUpdated(toUserProfileUpdatedEvent(updated))
								.thenReturn(toMeResponse(updated))
						}
					}
			}
	}

	override fun createProfileImageUploadUrl(
		user: AuthenticatedUser,
		request: CreateProfileImageUploadUrlRequest,
	): Mono<CreateProfileImageUploadUrlResponse> =
		Mono.fromSupplier {
			if (!profileImageProperties.enabled) {
				throw AppException(ErrorCode.FORBIDDEN, "Profile image upload is disabled.")
			}

			val bucket = profileImageProperties.normalizedBucket()
			if (bucket.isBlank()) {
				throw AppException(ErrorCode.INTERNAL_SERVER_ERROR, "Profile image bucket is not configured.")
			}

			val normalizedContentType = normalizeContentType(request.contentType)
			val allowedContentTypes = profileImageProperties.allowedContentTypesSet()
			if (allowedContentTypes.isNotEmpty() && normalizedContentType !in allowedContentTypes) {
				throw AppException(ErrorCode.INVALID_REQUEST, "Unsupported profile image content type.")
			}

			val extension = CONTENT_TYPE_TO_EXTENSION[normalizedContentType]
				?: throw AppException(ErrorCode.INVALID_REQUEST, "Unsupported profile image content type.")
			val objectKey = "${profileImageProperties.normalizedKeyPrefix()}/${user.userId}/${UUID.randomUUID()}$extension"
			val expiresInSeconds = profileImageProperties.uploadUrlExpirationSeconds
			if (expiresInSeconds < MIN_UPLOAD_URL_EXP_SECONDS || expiresInSeconds > MAX_UPLOAD_URL_EXP_SECONDS) {
				throw AppException(
					ErrorCode.INTERNAL_SERVER_ERROR,
					"Profile image upload URL expiration seconds must be between 60 and 3600.",
				)
			}

			val presigned = s3Presigner.presignPutObject(
				PutObjectPresignRequest.builder()
					.signatureDuration(Duration.ofSeconds(expiresInSeconds))
					.putObjectRequest(
						PutObjectRequest.builder()
							.bucket(bucket)
							.key(objectKey)
							.contentType(normalizedContentType)
							.build(),
					)
					.build(),
			)

			val profileImageUrl = buildProfileImageUrl(bucket, objectKey)
			validateProfileImageHost(profileImageUrl)
			CreateProfileImageUploadUrlResponse(
				uploadUrl = presigned.url().toString(),
				profileImageUrl = profileImageUrl,
				objectKey = objectKey,
				expiresInSeconds = expiresInSeconds,
			)
		}

	override fun changePassword(user: AuthenticatedUser, request: ChangePasswordRequest): Mono<ChangePasswordResponse> =
		userRepository.findById(user.userId)
			.switchIfEmpty(Mono.error(AppException(ErrorCode.NOT_FOUND, "User not found.")))
			.flatMap { entity ->
				if (!passwordService.matches(request.currentPassword, entity.passwordHash)) {
					Mono.error(AppException(ErrorCode.UNAUTHORIZED, "Invalid username or password."))
				} else {
					userRepository.save(
						entity.copy(
							passwordHash = passwordService.hash(request.newPassword),
							forcePasswordChange = false,
						),
					).map {
						logger.warn("security_audit event=password_changed user_id={}", it.id)
						ChangePasswordResponse(success = true)
					}
					}
				}

	private fun toMeResponse(entity: UserEntity): MeResponse =
		MeResponse(
			id = requireNotNull(entity.id),
			username = entity.username,
			role = entity.role,
			publicCode = entity.publicCode,
			nickname = entity.nickname,
			profileImageUrl = entity.profileImageUrl,
		)

	private fun toUserProfileUpdatedEvent(entity: UserEntity): UserProfileUpdatedEvent =
		UserProfileUpdatedEvent(
			eventId = UUID.randomUUID().toString(),
			type = USER_PROFILE_UPDATED_EVENT_TYPE,
			occurredAt = entity.updatedAt.toString(),
			userId = requireNotNull(entity.id).toString(),
			nickname = entity.nickname,
			profileImageUrl = entity.profileImageUrl,
			version = entity.profileVersion,
		)

	private fun normalizeNickname(raw: String): String {
		val normalized = raw.trim()
		if (normalized.isEmpty()) {
			throw AppException(ErrorCode.INVALID_REQUEST, "nickname must not be blank.")
		}
		if (!NICKNAME_PATTERN.matches(normalized)) {
			throw AppException(
				ErrorCode.INVALID_REQUEST,
				"nickname allows only letters, numbers, spaces, underscores, hyphens, and dots.",
			)
		}
		return normalized
	}

	private fun normalizeProfileImageUrl(raw: String): String {
		val normalized = raw.trim()
		if (normalized.isEmpty()) {
			throw AppException(ErrorCode.INVALID_REQUEST, "profileImageUrl must not be blank.")
		}
		val uri = try {
			URI(normalized)
		} catch (_: Exception) {
			null
		} ?: throw AppException(ErrorCode.INVALID_REQUEST, "profileImageUrl must be a valid https URL.")
		val scheme = uri.scheme?.lowercase()
		val host = uri.host?.lowercase()
		if (scheme != "https" || host.isNullOrBlank()) {
			throw AppException(ErrorCode.INVALID_REQUEST, "profileImageUrl must be a valid https URL.")
		}
		if (allowedImageHosts.isNotEmpty() && host !in allowedImageHosts) {
			throw AppException(ErrorCode.INVALID_REQUEST, "profileImageUrl host is not allowed.")
		}
		return normalized
	}

	private fun uploadProfileImage(userId: UUID, profileImage: FilePart): Mono<String> {
		if (!profileImageProperties.enabled) {
			return Mono.error(AppException(ErrorCode.FORBIDDEN, "Profile image upload is disabled."))
		}

		val bucket = profileImageProperties.normalizedBucket()
		if (bucket.isBlank()) {
			return Mono.error(AppException(ErrorCode.INTERNAL_SERVER_ERROR, "Profile image bucket is not configured."))
		}

		val normalizedContentType = profileImage.headers().contentType?.toString()?.let { normalizeContentType(it) }
			?: return Mono.error(AppException(ErrorCode.INVALID_REQUEST, "profileImage content type is required."))
		val allowedContentTypes = profileImageProperties.allowedContentTypesSet()
		if (allowedContentTypes.isNotEmpty() && normalizedContentType !in allowedContentTypes) {
			return Mono.error(AppException(ErrorCode.INVALID_REQUEST, "Unsupported profile image content type."))
		}
		val extension = CONTENT_TYPE_TO_EXTENSION[normalizedContentType]
			?: return Mono.error(AppException(ErrorCode.INVALID_REQUEST, "Unsupported profile image content type."))
		val objectKey = "${profileImageProperties.normalizedKeyPrefix()}/$userId/${UUID.randomUUID()}$extension"

		return Mono.usingWhen(
			Mono.fromCallable {
				Files.createTempFile("profile-image-$userId-", extension)
			}.subscribeOn(Schedulers.boundedElastic()),
			{ tempFile ->
				profileImage.transferTo(tempFile)
					.then(
						Mono.fromCallable {
							val size = Files.size(tempFile)
							if (size <= 0) {
								throw AppException(ErrorCode.INVALID_REQUEST, "profileImage must not be empty.")
							}
							if (size > profileImageProperties.maxUploadBytes) {
								throw AppException(
									ErrorCode.INVALID_REQUEST,
									"profileImage exceeds max size ${profileImageProperties.maxUploadBytes} bytes.",
								)
							}

							s3Client.putObject(
								PutObjectRequest.builder()
									.bucket(bucket)
									.key(objectKey)
									.contentType(normalizedContentType)
									.contentLength(size)
									.build(),
								RequestBody.fromFile(tempFile),
							)
							val profileImageUrl = buildProfileImageUrl(bucket, objectKey)
							validateProfileImageHost(profileImageUrl)
							profileImageUrl
						}.subscribeOn(Schedulers.boundedElastic()),
					)
			},
			{ tempFile -> deleteTempFile(tempFile) },
			{ tempFile, _ -> deleteTempFile(tempFile) },
			{ tempFile -> deleteTempFile(tempFile) },
		)
	}

	private fun normalizeContentType(raw: String): String =
		raw.trim().lowercase().substringBefore(";").trim()

	private fun buildProfileImageUrl(bucket: String, objectKey: String): String {
		val publicBaseUrl = profileImageProperties.normalizedPublicBaseUrl()
		return if (publicBaseUrl.isNotBlank()) {
			"$publicBaseUrl/$objectKey"
		} else {
			"https://$bucket.s3.${profileImageProperties.normalizedRegion()}.amazonaws.com/$objectKey"
		}
	}

	private fun validateProfileImageHost(profileImageUrl: String) {
		if (allowedImageHosts.isEmpty()) {
			return
		}
		val host = try {
			URI(profileImageUrl).host?.lowercase()
		} catch (_: Exception) {
			null
		}
		if (host.isNullOrBlank() || host !in allowedImageHosts) {
			throw AppException(
				ErrorCode.INTERNAL_SERVER_ERROR,
				"Generated profile image URL host is not allowed by profile configuration.",
			)
		}
	}

	private fun deleteTempFile(path: Path): Mono<Void> =
		Mono.fromCallable {
			try {
				Files.deleteIfExists(path)
			} catch (_: Exception) {
				// no-op
			}
			true
		}.subscribeOn(Schedulers.boundedElastic()).then()

	companion object {
		private val logger = LoggerFactory.getLogger(UserServiceImpl::class.java)
		private val NICKNAME_PATTERN = Regex("^[\\p{L}\\p{N} _.-]{1,40}$")
		private const val USER_PROFILE_UPDATED_EVENT_TYPE = "UserProfileUpdated"
		private const val MIN_UPLOAD_URL_EXP_SECONDS = 60L
		private const val MAX_UPLOAD_URL_EXP_SECONDS = 3600L
		private val CONTENT_TYPE_TO_EXTENSION = mapOf(
			"image/jpeg" to ".jpg",
			"image/png" to ".png",
			"image/webp" to ".webp",
		)
	}
}
