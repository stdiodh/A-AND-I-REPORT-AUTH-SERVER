package com.aandiclub.auth.admin.web.dto

import com.aandiclub.auth.user.domain.UserRole
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.Size
import java.time.Instant

data class InviteMailRequest(
	@field:Email(message = "email must be a valid email address")
	val email: String? = null,
	@field:Size(max = 100, message = "emails size must be less than or equal to 100")
	val emails: List<@Email(message = "emails must contain valid email addresses") String> = emptyList(),
	val role: UserRole = UserRole.USER,
) {
	fun recipientEmails(): List<String> =
		buildList {
			email?.trim()
				?.takeIf { it.isNotEmpty() }
				?.let { add(it) }
			emails.asSequence()
				.map { it.trim() }
				.filter { it.isNotEmpty() }
				.forEach { add(it) }
		}.distinctBy { it.lowercase() }
}

data class InviteMailTarget(
	val email: String,
	val username: String,
	val role: UserRole,
	val inviteExpiresAt: Instant,
)

data class InviteMailResponse(
	val sentCount: Int,
	val invites: List<InviteMailTarget>,
	val username: String? = null,
	val role: UserRole? = null,
	val inviteExpiresAt: Instant? = null,
)
