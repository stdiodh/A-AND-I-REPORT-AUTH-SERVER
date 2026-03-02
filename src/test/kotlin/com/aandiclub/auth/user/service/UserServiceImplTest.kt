package com.aandiclub.auth.user.service

import com.aandiclub.auth.common.error.AppException
import com.aandiclub.auth.common.error.ErrorCode
import com.aandiclub.auth.security.auth.AuthenticatedUser
import com.aandiclub.auth.security.service.PasswordService
import com.aandiclub.auth.user.config.ProfileImageProperties
import com.aandiclub.auth.user.config.ProfileProperties
import com.aandiclub.auth.user.domain.UserEntity
import com.aandiclub.auth.user.domain.UserRole
import com.aandiclub.auth.user.event.UserProfileEventPublisher
import com.aandiclub.auth.user.event.UserProfileUpdatedEvent
import com.aandiclub.auth.user.repository.UserRepository
import com.aandiclub.auth.user.service.impl.UserServiceImpl
import com.aandiclub.auth.user.web.dto.CreateProfileImageUploadUrlRequest
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.http.codec.multipart.FilePart
import reactor.core.publisher.Mono
import reactor.test.StepVerifier
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider
import software.amazon.awssdk.core.sync.RequestBody
import software.amazon.awssdk.regions.Region
import software.amazon.awssdk.services.s3.S3Client
import software.amazon.awssdk.services.s3.model.PutObjectRequest
import software.amazon.awssdk.services.s3.model.PutObjectResponse
import software.amazon.awssdk.services.s3.presigner.S3Presigner
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.UUID

class UserServiceImplTest : FunSpec({
	val userRepository = mockk<UserRepository>()
	val passwordService = mockk<PasswordService>()
	val userProfileEventPublisher = mockk<UserProfileEventPublisher>()
	val s3Client = mockk<S3Client>()
	val s3Presigner = S3Presigner.builder()
		.region(Region.AP_NORTHEAST_2)
		.credentialsProvider(
			StaticCredentialsProvider.create(
				AwsBasicCredentials.create("test-access-key", "test-secret-key"),
			),
		)
		.build()
	val service = UserServiceImpl(
		userRepository = userRepository,
		passwordService = passwordService,
		userPublicCodeService = UserPublicCodeService(),
		userProfileEventPublisher = userProfileEventPublisher,
		profileImageProperties = ProfileImageProperties(
			enabled = true,
			bucket = "my-images",
			region = "ap-northeast-2",
			keyPrefix = "profiles",
			publicBaseUrl = "",
			uploadUrlExpirationSeconds = 600,
			maxUploadBytes = 5_242_880,
			allowedContentTypes = "image/jpeg,image/png,image/webp",
		),
		s3Presigner = s3Presigner,
		s3Client = s3Client,
		profileProperties = ProfileProperties(
			allowedImageHosts = "images.aandiclub.com,profile-bucket.s3.ap-northeast-2.amazonaws.com,my-images.s3.ap-northeast-2.amazonaws.com",
		),
	)
	every { userProfileEventPublisher.publishUserProfileUpdated(any()) } returns Mono.empty()

	test("getMe should return persisted profile fields") {
		val userId = UUID.randomUUID()
		every { userRepository.findById(userId) } returns Mono.just(
			UserEntity(
				id = userId,
				username = "user_01",
				passwordHash = "hash",
				role = UserRole.USER,
				nickname = "홍길동",
				profileImageUrl = "https://images.aandiclub.com/users/user_01.png",
				createdAt = Instant.now(),
				updatedAt = Instant.now(),
			),
		)

		StepVerifier.create(service.getMe(AuthenticatedUser(userId, "user_01", UserRole.USER)))
			.assertNext { response ->
				response.publicCode shouldBe "#NO001"
				response.nickname shouldBe "홍길동"
				response.profileImageUrl shouldBe "https://images.aandiclub.com/users/user_01.png"
			}
			.verifyComplete()
	}

	test("updateProfile should update nickname without password check") {
		val userId = UUID.randomUUID()
		val entity = UserEntity(
			id = userId,
			username = "user_02",
			passwordHash = "hash",
			role = UserRole.USER,
			nickname = "old",
			profileImageUrl = "https://images.aandiclub.com/old.png",
			createdAt = Instant.now(),
			updatedAt = Instant.now(),
		)

		every { userRepository.findById(userId) } returns Mono.just(entity)
		every { userRepository.save(any()) } answers { Mono.just(firstArg()) }
		val eventSlot = slot<UserProfileUpdatedEvent>()
		every { userProfileEventPublisher.publishUserProfileUpdated(capture(eventSlot)) } returns Mono.empty()

		StepVerifier.create(service.updateProfile(AuthenticatedUser(userId, "user_02", UserRole.USER), "new profile", null, null))
			.assertNext { response ->
				response.nickname shouldBe "new profile"
				response.profileImageUrl shouldBe "https://images.aandiclub.com/old.png"
			}
			.verifyComplete()

		verify(exactly = 0) { passwordService.matches(any(), any()) }
		verify(atLeast = 1) { userProfileEventPublisher.publishUserProfileUpdated(any()) }
		eventSlot.captured.type shouldBe "UserProfileUpdated"
		eventSlot.captured.userId shouldBe userId.toString()
		eventSlot.captured.nickname shouldBe "new profile"
		eventSlot.captured.profileImageUrl shouldBe "https://images.aandiclub.com/old.png"
		eventSlot.captured.version shouldBe 1L
	}

	test("updateProfile should reject empty payload") {
		StepVerifier.create(
			service.updateProfile(
				AuthenticatedUser(UUID.randomUUID(), "user_03", UserRole.USER),
				null,
				null,
				null,
			),
		)
			.expectErrorSatisfies { ex ->
				ex::class shouldBe AppException::class
				(ex as AppException).errorCode shouldBe ErrorCode.INVALID_REQUEST
				ex.message shouldBe "At least one profile field is required."
			}
			.verify()
	}

	test("updateProfile should upload image to s3 and save generated url") {
		val userId = UUID.randomUUID()
		val entity = UserEntity(
			id = userId,
			username = "user_04",
			passwordHash = "hash",
			role = UserRole.USER,
			nickname = "old",
			profileImageUrl = null,
			createdAt = Instant.now(),
			updatedAt = Instant.now(),
		)
		val filePart = mockk<FilePart>()
		val headers = HttpHeaders().apply { contentType = MediaType.IMAGE_PNG }

		every { filePart.headers() } returns headers
		every { filePart.transferTo(any<Path>()) } answers {
			Files.write(firstArg(), byteArrayOf(1, 2, 3, 4))
			Mono.empty()
		}
		every { userRepository.findById(userId) } returns Mono.just(entity)
		every { s3Client.putObject(any<PutObjectRequest>(), any<RequestBody>()) } returns PutObjectResponse.builder().build()
		every { userRepository.save(any()) } answers { Mono.just(firstArg()) }

		StepVerifier.create(
			service.updateProfile(
				AuthenticatedUser(userId, "user_04", UserRole.USER),
				"new profile",
				filePart,
				null,
			),
		)
			.assertNext { response ->
				response.nickname shouldBe "new profile"
				response.profileImageUrl shouldContain "https://my-images.s3.ap-northeast-2.amazonaws.com/profiles/$userId/"
			}
			.verifyComplete()
	}

	test("updateProfile should reject unsupported multipart image content type") {
		val userId = UUID.randomUUID()
		val filePart = mockk<FilePart>()
		val headers = HttpHeaders().apply { contentType = MediaType.IMAGE_GIF }
		val entity = UserEntity(
			id = userId,
			username = "user_05",
			passwordHash = "hash",
			role = UserRole.USER,
			createdAt = Instant.now(),
			updatedAt = Instant.now(),
		)
		every { filePart.headers() } returns headers
		every { userRepository.findById(userId) } returns Mono.just(entity)

		StepVerifier.create(
			service.updateProfile(
				AuthenticatedUser(userId, "user_05", UserRole.USER),
				"new profile",
				filePart,
				null,
			),
		)
			.expectErrorSatisfies { ex ->
				ex::class shouldBe AppException::class
				(ex as AppException).errorCode shouldBe ErrorCode.INVALID_REQUEST
				ex.message shouldBe "Unsupported profile image content type."
			}
			.verify()
	}

	test("createProfileImageUploadUrl should return presigned url and public image url") {
		val userId = UUID.randomUUID()

		StepVerifier.create(
			service.createProfileImageUploadUrl(
				AuthenticatedUser(userId, "user_05", UserRole.USER),
				CreateProfileImageUploadUrlRequest(
					contentType = "image/png",
					fileName = "avatar.png",
				),
			),
		)
			.assertNext { response ->
				response.uploadUrl shouldContain "X-Amz-Signature="
				response.profileImageUrl shouldContain "https://my-images.s3.ap-northeast-2.amazonaws.com/profiles/$userId/"
				response.objectKey shouldContain "profiles/$userId/"
				response.expiresInSeconds shouldBe 600
			}
			.verifyComplete()
	}

	test("updateProfile should update profile image url and publish event") {
		val userId = UUID.randomUUID()
		val entity = UserEntity(
			id = userId,
			username = "user_07",
			passwordHash = "hash",
			role = UserRole.USER,
			nickname = "old",
			profileImageUrl = "https://images.aandiclub.com/old.png",
			createdAt = Instant.now(),
			updatedAt = Instant.now(),
		)
		val newProfileImageUrl = "https://images.aandiclub.com/new.png"

		every { userRepository.findById(userId) } returns Mono.just(entity)
		every { userRepository.save(any()) } answers { Mono.just(firstArg()) }
		val eventSlot = slot<UserProfileUpdatedEvent>()
		every { userProfileEventPublisher.publishUserProfileUpdated(capture(eventSlot)) } returns Mono.empty()

		StepVerifier.create(
			service.updateProfile(
				AuthenticatedUser(userId, "user_07", UserRole.USER),
				null,
				null,
				newProfileImageUrl,
			),
		)
			.assertNext { response ->
				response.nickname shouldBe "old"
				response.profileImageUrl shouldBe newProfileImageUrl
			}
			.verifyComplete()

		verify(atLeast = 1) { userProfileEventPublisher.publishUserProfileUpdated(any()) }
		eventSlot.captured.type shouldBe "UserProfileUpdated"
		eventSlot.captured.userId shouldBe userId.toString()
		eventSlot.captured.profileImageUrl shouldBe newProfileImageUrl
		eventSlot.captured.version shouldBe 1L
	}

	test("createProfileImageUploadUrl should reject unsupported content type") {
		StepVerifier.create(
			service.createProfileImageUploadUrl(
				AuthenticatedUser(UUID.randomUUID(), "user_06", UserRole.USER),
				CreateProfileImageUploadUrlRequest(contentType = "image/gif"),
			),
		)
			.expectErrorSatisfies { ex ->
				ex::class shouldBe AppException::class
				(ex as AppException).errorCode shouldBe ErrorCode.INVALID_REQUEST
				ex.message shouldBe "Unsupported profile image content type."
			}
			.verify()
	}

	test("lookupByPublicCode should return non-admin user") {
		val userId = UUID.randomUUID()
		every { userRepository.findByPublicCode("#NO001") } returns Mono.just(
			UserEntity(
				id = userId,
				username = "lookup_user",
				passwordHash = "hash",
				role = UserRole.USER,
				publicCode = "#NO001",
				nickname = "닉네임",
			),
		)

		StepVerifier.create(service.lookupByPublicCode("#NO001"))
			.assertNext { response ->
				response.id shouldBe userId
				response.publicCode shouldBe "#NO001"
				response.username shouldBe "lookup_user"
			}
			.verifyComplete()
	}

	test("lookupByPublicCode should reject admin user") {
		every { userRepository.findByPublicCode("#AD001") } returns Mono.just(
			UserEntity(
				id = UUID.randomUUID(),
				username = "admin_lookup",
				passwordHash = "hash",
				role = UserRole.ADMIN,
				publicCode = "#AD001",
			),
		)

		StepVerifier.create(service.lookupByPublicCode("#AD001"))
			.expectErrorSatisfies { ex ->
				(ex as AppException).errorCode shouldBe ErrorCode.NOT_FOUND
			}
			.verify()
	}

	afterSpec {
		s3Presigner.close()
	}
})
