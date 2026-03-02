package com.aandiclub.auth.user.web.dto

import com.aandiclub.auth.user.domain.UserRole
import java.util.UUID

data class UserLookupResponse(
	val id: UUID,
	val username: String,
	val role: UserRole,
	val publicCode: String,
	val nickname: String? = null,
	val profileImageUrl: String? = null,
)
