package com.aandiclub.auth.security

import com.aandiclub.auth.security.service.JwtService
import com.aandiclub.auth.user.domain.UserRole
import io.kotest.core.extensions.Extension
import io.kotest.core.spec.style.StringSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.shouldBe
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.ApplicationContext
import org.springframework.http.HttpMethod
import org.springframework.http.MediaType
import org.springframework.core.io.ByteArrayResource
import org.springframework.r2dbc.core.DatabaseClient
import org.springframework.http.client.MultipartBodyBuilder
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.reactive.server.WebTestClient
import java.time.Instant
import java.util.UUID

@SpringBootTest
@TestPropertySource(
	properties = [
		"spring.r2dbc.url=r2dbc:h2:mem:///authzdb;DB_CLOSE_DELAY=-1;MODE=PostgreSQL",
		"spring.r2dbc.username=sa",
		"spring.r2dbc.password=",
	],
)
class AuthorizationMatrixTest : StringSpec() {

	@Autowired
	private lateinit var applicationContext: ApplicationContext

	@Autowired
	private lateinit var jwtService: JwtService

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
						"force_password_change" BOOLEAN NOT NULL DEFAULT FALSE,
						"is_active" BOOLEAN NOT NULL DEFAULT TRUE,
						"last_login_at" TIMESTAMP NULL,
						"nickname" VARCHAR(40) NULL,
						"profile_image_url" VARCHAR(2048) NULL,
						"profile_version" BIGINT NOT NULL DEFAULT 0,
						"user_track" VARCHAR(16) NOT NULL DEFAULT 'NO',
						"cohort" INTEGER NOT NULL DEFAULT 0,
						"cohort_order" INTEGER NOT NULL DEFAULT 0,
						"public_code" VARCHAR(16) NOT NULL,
						"created_at" TIMESTAMP NOT NULL,
						"updated_at" TIMESTAMP NOT NULL
					)
					""".trimIndent(),
				).fetch().rowsUpdated().block()
				databaseClient.sql(
					"""
					CREATE TABLE IF NOT EXISTS "user_invites" (
						"id" UUID PRIMARY KEY,
						"user_id" UUID NOT NULL,
						"token_hash" VARCHAR(128) NOT NULL UNIQUE,
						"expires_at" TIMESTAMP NOT NULL,
						"used_at" TIMESTAMP NULL,
						"created_at" TIMESTAMP NOT NULL,
						CONSTRAINT "fk_user_invites_user_id" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE
					)
					""".trimIndent(),
				).fetch().rowsUpdated().block()
			}

			beforeTest {
				databaseClient.sql("""DELETE FROM "user_invites"""").fetch().rowsUpdated().block()
				databaseClient.sql("""DELETE FROM "users"""").fetch().rowsUpdated().block()
			}

		"GET /v1/me requires authentication" {
			webClient().get()
				.uri("/v1/me")
				.exchange()
				.expectStatus().isUnauthorized
		}

		"GET /v1/me allows USER role" {
			val userId = UUID.randomUUID()
			val username = "tester_user"
			insertUser(userId, username, UserRole.USER)
			val token = accessToken(userId, username, UserRole.USER)
			webClient().get()
				.uri("/v1/me")
				.headers { it.setBearerAuth(token) }
				.exchange()
				.expectStatus().isOk
				.expectBody()
				.jsonPath("$.success").isEqualTo(true)
				.jsonPath("$.data.username").isEqualTo(username)
				.jsonPath("$.data.role").isEqualTo("USER")
		}

		"POST /v1/me with multipart requires authentication" {
			webClient().post()
				.uri("/v1/me")
				.contentType(MediaType.MULTIPART_FORM_DATA)
				.body(BodyInserters.fromMultipartData("nickname", "new profile"))
				.exchange()
				.expectStatus().isUnauthorized
		}

		"PATCH /v1/me with json requires authentication" {
			webClient().patch()
				.uri("/v1/me")
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue("""{"nickname":"new profile"}""")
				.exchange()
				.expectStatus().isUnauthorized
		}

		"POST /v1/me/profile-image/upload-url requires authentication" {
			webClient().post()
				.uri("/v1/me/profile-image/upload-url")
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue("""{"contentType":"image/png","fileName":"avatar.png"}""")
				.exchange()
				.expectStatus().isUnauthorized
		}

		"POST /v1/me with multipart allows USER role" {
			val userId = UUID.randomUUID()
			val username = "tester_profile"
			insertUser(userId, username, UserRole.USER)
			val token = accessToken(userId, username, UserRole.USER)

			webClient().post()
				.uri("/v1/me")
				.headers { it.setBearerAuth(token) }
				.contentType(MediaType.MULTIPART_FORM_DATA)
				.body(BodyInserters.fromMultipartData("nickname", "new profile"))
				.exchange()
				.expectStatus().isOk
				.expectBody()
				.jsonPath("$.success").isEqualTo(true)
				.jsonPath("$.data.nickname").isEqualTo("new profile")
		}

		"PATCH /v1/me with json allows USER role" {
			val userId = UUID.randomUUID()
			val username = "tester_profile_json"
			insertUser(userId, username, UserRole.USER)
			val token = accessToken(userId, username, UserRole.USER)

			webClient().patch()
				.uri("/v1/me")
				.headers { it.setBearerAuth(token) }
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue("""{"nickname":"new profile"}""")
				.exchange()
				.expectStatus().isOk
				.expectBody()
				.jsonPath("$.success").isEqualTo(true)
				.jsonPath("$.data.nickname").isEqualTo("new profile")
		}

		"PATCH /v1/me with profileImageUrl allows USER role" {
			val userId = UUID.randomUUID()
			val username = "tester_profile_image_json"
			insertUser(userId, username, UserRole.USER)
			val token = accessToken(userId, username, UserRole.USER)

			webClient().patch()
				.uri("/v1/me")
				.headers { it.setBearerAuth(token) }
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue("""{"profileImageUrl":"https://images.aandiclub.com/users/avatar.png"}""")
				.exchange()
				.expectStatus().isOk
				.expectBody()
				.jsonPath("$.success").isEqualTo(true)
				.jsonPath("$.data.profileImageUrl").isEqualTo("https://images.aandiclub.com/users/avatar.png")
		}

		"POST /v1/me with multipart file is parsed (not 415) and rejected by policy when upload disabled" {
			val userId = UUID.randomUUID()
			val username = "tester_profile_file"
			insertUser(userId, username, UserRole.USER)
			val token = accessToken(userId, username, UserRole.USER)

			val multipart = MultipartBodyBuilder().apply {
				part("nickname", "new profile")
				part("profileImage", object : ByteArrayResource("fake-png".toByteArray()) {
					override fun getFilename(): String = "avatar.png"
				}).contentType(MediaType.IMAGE_PNG)
			}.build()

			webClient().post()
				.uri("/v1/me")
				.headers { it.setBearerAuth(token) }
				.contentType(MediaType.MULTIPART_FORM_DATA)
				.body(BodyInserters.fromMultipartData(multipart))
				.exchange()
				.expectStatus().isForbidden
				.expectBody()
				.jsonPath("$.success").isEqualTo(false)
				.jsonPath("$.error.code").isEqualTo("FORBIDDEN")
		}

		"GET /v1/admin/ping denies USER role" {
			val token = accessToken(UUID.randomUUID(), "tester_user_denied", UserRole.USER)
			webClient().get()
				.uri("/v1/admin/ping")
				.headers { it.setBearerAuth(token) }
				.exchange()
				.expectStatus().isForbidden
		}

		"GET /v1/admin/ping denies ORGANIZER role" {
			val token = accessToken(UUID.randomUUID(), "tester_organizer_denied", UserRole.ORGANIZER)
			webClient().get()
				.uri("/v1/admin/ping")
				.headers { it.setBearerAuth(token) }
				.exchange()
				.expectStatus().isForbidden
		}

		"POST /v1/admin/invite-mail denies USER role" {
			val token = accessToken(UUID.randomUUID(), "tester_user_invite_mail_denied", UserRole.USER)
			webClient().post()
				.uri("/v1/admin/invite-mail")
				.headers { it.setBearerAuth(token) }
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue("""{"email":"new_member@aandi.club","role":"USER"}""")
				.exchange()
				.expectStatus().isForbidden
		}

			"GET /v1/admin/ping allows ADMIN role" {
				val token = accessToken(UUID.randomUUID(), "tester_admin", UserRole.ADMIN)
				webClient().get()
					.uri("/v1/admin/ping")
				.headers { it.setBearerAuth(token) }
				.exchange()
				.expectStatus().isOk
				.expectBody()
					.jsonPath("$.success").isEqualTo(true)
					.jsonPath("$.data.ok").isEqualTo(true)
			}

			"PATCH /v1/admin/users/role denies USER role" {
				val targetUserId = UUID.randomUUID()
				val token = accessToken(UUID.randomUUID(), "tester_user_role_patch_denied", UserRole.USER)
				webClient().patch()
					.uri("/v1/admin/users/role")
					.headers { it.setBearerAuth(token) }
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("""{"userId":"$targetUserId","role":"ORGANIZER"}""")
					.exchange()
					.expectStatus().isForbidden
			}

			"PATCH /v1/admin/users/role denies ORGANIZER role" {
				val targetUserId = UUID.randomUUID()
				val token = accessToken(UUID.randomUUID(), "tester_organizer_role_patch_denied", UserRole.ORGANIZER)
				webClient().patch()
					.uri("/v1/admin/users/role")
					.headers { it.setBearerAuth(token) }
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("""{"userId":"$targetUserId","role":"USER"}""")
					.exchange()
					.expectStatus().isForbidden
			}

			"PATCH /v1/admin/users/role allows ADMIN role" {
				val targetUserId = UUID.randomUUID()
				insertUser(targetUserId, "target_role_user", UserRole.USER)
				val token = accessToken(UUID.randomUUID(), "tester_admin_role_patch_allowed", UserRole.ADMIN)

				webClient().patch()
					.uri("/v1/admin/users/role")
					.headers { it.setBearerAuth(token) }
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("""{"userId":"$targetUserId","role":"ORGANIZER"}""")
					.exchange()
					.expectStatus().isOk
					.expectBody()
					.jsonPath("$.success").isEqualTo(true)
					.jsonPath("$.data.id").isEqualTo(targetUserId.toString())
					.jsonPath("$.data.role").isEqualTo("ORGANIZER")
			}

			"DELETE /v1/admin/users denies USER role" {
				val targetUserId = UUID.randomUUID()
				val token = accessToken(UUID.randomUUID(), "tester_user_delete_denied", UserRole.USER)
				webClient().method(HttpMethod.DELETE)
					.uri("/v1/admin/users")
					.headers { it.setBearerAuth(token) }
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("""{"userId":"$targetUserId"}""")
					.exchange()
					.expectStatus().isForbidden
			}

			"DELETE /v1/admin/users allows ADMIN role" {
				val targetUserId = UUID.randomUUID()
				insertUser(targetUserId, "target_delete_user", UserRole.USER)
				val token = accessToken(UUID.randomUUID(), "tester_admin_delete_allowed", UserRole.ADMIN)

				webClient().method(HttpMethod.DELETE)
					.uri("/v1/admin/users")
					.headers { it.setBearerAuth(token) }
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("""{"userId":"$targetUserId"}""")
					.exchange()
					.expectStatus().isNoContent

				userExists(targetUserId) shouldBe false
			}
		}

	private fun webClient(): WebTestClient = WebTestClient.bindToApplicationContext(applicationContext).build()

	private fun accessToken(userId: UUID, username: String, role: UserRole): String =
		jwtService.issueAccessToken(userId, username, role).value

	private fun insertUser(userId: UUID, username: String, role: UserRole) {
		databaseClient.sql(
			"""
				INSERT INTO "users" (
					"id",
					"username",
					"password_hash",
					"role",
					"force_password_change",
					"is_active",
					"last_login_at",
					"nickname",
					"profile_image_url",
					"profile_version",
					"user_track",
					"cohort",
					"cohort_order",
					"public_code",
					"created_at",
					"updated_at"
				) VALUES (
					:userId,
					:username,
				:passwordHash,
				:role,
				:forcePasswordChange,
				:isActive,
					:lastLoginAt,
					:nickname,
					:profileImageUrl,
					:profileVersion,
					:userTrack,
					:cohort,
					:cohortOrder,
					:publicCode,
					:createdAt,
					:updatedAt
				)
			""".trimIndent(),
		)
			.bind("userId", userId)
			.bind("username", username)
			.bind("passwordHash", "hash")
			.bind("role", role.name)
			.bind("forcePasswordChange", false)
			.bind("isActive", true)
			.bindNull("lastLoginAt", Instant::class.java)
				.bindNull("nickname", String::class.java)
				.bindNull("profileImageUrl", String::class.java)
				.bind("profileVersion", 0L)
				.bind("userTrack", "NO")
				.bind("cohort", 0)
				.bind("cohortOrder", 0)
				.bind("publicCode", userId.toString().replace("-", "").take(16))
				.bind("createdAt", Instant.now())
				.bind("updatedAt", Instant.now())
			.fetch()
			.rowsUpdated()
			.block()
	}

	private fun userExists(userId: UUID): Boolean {
		val row = databaseClient.sql("""SELECT COUNT(1) AS cnt FROM "users" WHERE "id" = :userId""")
			.bind("userId", userId)
			.fetch()
			.one()
			.block()
		return ((row?.get("cnt") as Number).toLong() > 0)
	}
}
