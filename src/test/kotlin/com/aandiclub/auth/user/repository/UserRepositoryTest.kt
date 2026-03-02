package com.aandiclub.auth.user.repository

import com.aandiclub.auth.user.domain.UserEntity
import com.aandiclub.auth.user.domain.UserRole
import io.kotest.core.extensions.Extension
import io.kotest.core.spec.style.FunSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.shouldBe
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.dao.DataIntegrityViolationException
import org.springframework.test.context.TestPropertySource
import org.springframework.r2dbc.core.DatabaseClient
import reactor.test.StepVerifier
import java.time.Instant

@SpringBootTest
@TestPropertySource(
		properties = [
		"spring.r2dbc.url=r2dbc:h2:mem:///authdb;DB_CLOSE_DELAY=-1;MODE=PostgreSQL",
		"spring.r2dbc.username=sa",
		"spring.r2dbc.password=",
	],
)
class UserRepositoryTest : FunSpec() {

	@Autowired
	private lateinit var userRepository: UserRepository

	@Autowired
	private lateinit var databaseClient: DatabaseClient

	override fun extensions(): List<Extension> = listOf(SpringExtension)

	init {
		beforeSpec {
			databaseClient.sql(
				"""
				CREATE TABLE IF NOT EXISTS "users" (
					"id" UUID PRIMARY KEY,
					"username" VARCHAR(64) NOT NULL UNIQUE,
					"password_hash" VARCHAR(255) NOT NULL,
					"role" VARCHAR(32) NOT NULL,
					"user_track" VARCHAR(16) NOT NULL,
					"cohort" INTEGER NOT NULL,
					"cohort_order" INTEGER NOT NULL,
					"public_code" VARCHAR(16) NOT NULL UNIQUE,
					"force_password_change" BOOLEAN NOT NULL,
					"is_active" BOOLEAN NOT NULL,
					"last_login_at" TIMESTAMP NULL,
					"nickname" VARCHAR(40) NULL,
					"profile_image_url" VARCHAR(2048) NULL,
					"profile_version" BIGINT NOT NULL DEFAULT 0,
					"created_at" TIMESTAMP NOT NULL,
					"updated_at" TIMESTAMP NOT NULL
				)
				""".trimIndent(),
			).fetch().rowsUpdated().block()
		}

		beforeTest {
			databaseClient.sql("""DELETE FROM "users"""").fetch().rowsUpdated().block()
		}

		test("save and findByUsername should work") {
			val saved = userRepository.save(
				UserEntity(
					username = "user_01",
					passwordHash = "hashed-password",
					role = UserRole.USER,
					createdAt = Instant.now(),
					updatedAt = Instant.now(),
				),
			)

			StepVerifier.create(saved)
				.expectNextCount(1)
				.verifyComplete()

			StepVerifier.create(userRepository.findByUsername("user_01"))
				.assertNext { user ->
					user.username shouldBe "user_01"
					user.role shouldBe UserRole.USER
				}
				.verifyComplete()

			StepVerifier.create(userRepository.findByPublicCode("#NO001"))
				.assertNext { user ->
					user.username shouldBe "user_01"
				}
				.verifyComplete()
		}

		test("username should be unique") {
			val username = "user_unique"
			val first = userRepository.save(
				UserEntity(
					username = username,
					passwordHash = "hashed-password-1",
					role = UserRole.USER,
					createdAt = Instant.now(),
					updatedAt = Instant.now(),
				),
			)

			val duplicate = userRepository.save(
				UserEntity(
					username = username,
					passwordHash = "hashed-password-2",
					role = UserRole.ORGANIZER,
					createdAt = Instant.now(),
					updatedAt = Instant.now(),
				),
			)

			StepVerifier.create(first)
				.expectNextCount(1)
				.verifyComplete()

			StepVerifier.create(duplicate)
				.expectError(DataIntegrityViolationException::class.java)
				.verify()
		}

		test("save should persist profile fields") {
			val saved = userRepository.save(
				UserEntity(
					username = "user_profile",
					passwordHash = "hashed-password",
					role = UserRole.USER,
					nickname = "홍길동",
					profileImageUrl = "https://cdn.example.com/profile/user_profile.png",
					createdAt = Instant.now(),
					updatedAt = Instant.now(),
				),
			)

			StepVerifier.create(saved)
				.assertNext { user ->
					user.nickname shouldBe "홍길동"
					user.profileImageUrl shouldBe "https://cdn.example.com/profile/user_profile.png"
				}
				.verifyComplete()
		}
	}
}
