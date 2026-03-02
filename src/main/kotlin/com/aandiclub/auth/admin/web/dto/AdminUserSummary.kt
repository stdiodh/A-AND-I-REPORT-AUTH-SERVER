package com.aandiclub.auth.admin.web.dto

import com.aandiclub.auth.user.domain.UserRole
import com.aandiclub.auth.user.domain.UserTrack
import jakarta.validation.constraints.Max
import jakarta.validation.constraints.Min
import java.time.Instant
import java.util.UUID

data class AdminUserSummary(
	val id: UUID,
	val username: String,
	val role: UserRole,
	val userTrack: UserTrack,
	val cohort: Int,
	val cohortOrder: Int,
	val publicCode: String,
	val isActive: Boolean,
	val forcePasswordChange: Boolean,
	val inviteLink: String? = null,
	val inviteExpiresAt: Instant? = null,
)

data class CreateAdminUserRequest(
	@field:Min(0, message = "cohort must be between 0 and 9")
	@field:Max(9, message = "cohort must be between 0 and 9")
	val cohort: Int,
	val role: UserRole = UserRole.USER,
	val provisionType: ProvisionType = ProvisionType.INVITE,
	val cohort: Int? = null,
	val cohortOrder: Int? = null,
	val userTrack: String? = null,
)

data class CreateAdminUserResponse(
	val id: UUID,
	val username: String,
	val role: UserRole,
	val userTrack: UserTrack,
	val cohort: Int,
	val cohortOrder: Int,
	val publicCode: String,
	val provisionType: ProvisionType,
	val inviteLink: String? = null,
	val expiresAt: Instant? = null,
	val temporaryPassword: String? = null,
	val cohort: Int = 0,
	val cohortOrder: Int = 0,
	val userTrack: String = "NO",
	val publicCode: String? = null,
)

data class ResetPasswordResponse(
	val temporaryPassword: String,
)

data class UpdateUserRoleRequest(
	val userId: UUID,
	val role: UserRole,
	val userTrack: UserTrack? = null,
	@field:Min(0, message = "cohort must be between 0 and 9")
	@field:Max(9, message = "cohort must be between 0 and 9")
	val cohort: Int? = null,
)

data class UpdateUserRoleResponse(
	val id: UUID,
	val username: String,
	val role: UserRole,
	val userTrack: UserTrack,
	val cohort: Int,
	val cohortOrder: Int,
	val publicCode: String,
)

data class DeleteUserRequest(
	val userId: UUID,
)

enum class ProvisionType {
	INVITE,
	PASSWORD,
}
