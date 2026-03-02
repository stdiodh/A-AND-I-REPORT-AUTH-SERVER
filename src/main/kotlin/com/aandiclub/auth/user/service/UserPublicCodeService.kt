package com.aandiclub.auth.user.service

import com.aandiclub.auth.common.error.AppException
import com.aandiclub.auth.common.error.ErrorCode
import com.aandiclub.auth.user.domain.UserRole
import com.aandiclub.auth.user.domain.UserTrack
import org.springframework.stereotype.Component

@Component
class UserPublicCodeService {
	fun generate(role: UserRole, userTrack: UserTrack, cohort: Int, cohortOrder: Int): String {
		if (cohort !in MIN_COHORT..MAX_COHORT) {
			throw AppException(ErrorCode.INVALID_REQUEST, "cohort must be between 0 and 9.")
		}
		if (cohortOrder !in MIN_ORDER..MAX_ORDER) {
			throw AppException(ErrorCode.INTERNAL_SERVER_ERROR, "cohort order is out of supported range.")
		}
		val prefix = resolvePrefix(role, userTrack)
		return "#$prefix$cohort${cohortOrder.toString().padStart(2, '0')}"
	}

	fun normalizeLookupCode(rawCode: String): String {
		val trimmed = rawCode.trim().uppercase()
		val normalized = if (trimmed.startsWith("#")) trimmed else "#$trimmed"
		if (!LOOKUP_PATTERN.matches(normalized)) {
			throw AppException(ErrorCode.INVALID_REQUEST, "Invalid user code format.")
		}
		return normalized
	}

	fun resolveTrack(role: UserRole, requestedTrack: UserTrack?): UserTrack =
		if (role == UserRole.USER) {
			requestedTrack ?: UserTrack.NO
		} else {
			UserTrack.NO
		}

	private fun resolvePrefix(role: UserRole, userTrack: UserTrack): String = when (role) {
		UserRole.USER -> when (userTrack) {
			UserTrack.FL -> "FL"
			UserTrack.SP -> "SP"
			UserTrack.NO -> "NO"
		}
		UserRole.ORGANIZER -> "OR"
		UserRole.ADMIN -> "AD"
	}

	companion object {
		private const val MIN_COHORT = 0
		private const val MAX_COHORT = 9
		private const val MIN_ORDER = 1
		private const val MAX_ORDER = 99
		private val LOOKUP_PATTERN = Regex("^#[A-Z]{2}\\d{3}$")
	}
}
