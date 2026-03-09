package com.aandiclub.auth.admin.web.dto

import com.aandiclub.auth.user.domain.UserRole
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.Min
import jakarta.validation.constraints.NotEmpty
import jakarta.validation.constraints.Size
import jakarta.validation.Valid
import java.time.Instant

data class InviteMailRequest(
	@field:Valid
	@field:NotEmpty(message = "emails must not be empty")
	@field:Size(max = 100, message = "emails size must be less than or equal to 100")
	val emails: List<@Email(message = "emails must contain valid email addresses") String>,
	val role: UserRole = UserRole.USER,
	@field:Min(value = 0, message = "cohort must be greater than or equal to 0")
	val cohort: Int? = null,
	@field:Min(value = 0, message = "cohortOrder must be greater than or equal to 0")
	val cohortOrder: Int? = null,
	val userTrack: String? = null,
) {
	fun recipientEmails(): List<String> =
		emails.asSequence()
			.map { it.trim() }
			.filter { it.isNotEmpty() }
			.toList()
			.distinctBy { it.lowercase() }
}

data class InviteMailTarget(
	val email: String,
	val username: String,
	val role: UserRole,
	val inviteExpiresAt: Instant,
	val cohort: Int = 0,
	val cohortOrder: Int = 0,
	val userTrack: String = "NO",
	val publicCode: String? = null,
)

data class InviteMailResponse(
	val sentCount: Int,
	val invites: List<InviteMailTarget>,
	val username: String? = null,
	val role: UserRole? = null,
	val inviteExpiresAt: Instant? = null,
	val cohort: Int? = null,
	val cohortOrder: Int? = null,
	val userTrack: String? = null,
	val publicCode: String? = null,
)
