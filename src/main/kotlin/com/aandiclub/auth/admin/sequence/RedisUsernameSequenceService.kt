package com.aandiclub.auth.admin.sequence

import com.aandiclub.auth.common.error.AppException
import com.aandiclub.auth.common.error.ErrorCode
import org.springframework.data.redis.core.ReactiveStringRedisTemplate
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono

@Service
class RedisUsernameSequenceService(
	private val redisTemplate: ReactiveStringRedisTemplate,
) : UsernameSequenceService {
	override fun nextSequence(): Mono<Long> =
		redisTemplate.opsForValue().increment(KEY)
			.switchIfEmpty(Mono.error(AppException(ErrorCode.INTERNAL_SERVER_ERROR, "Failed to allocate username sequence.")))

	override fun nextCohortOrderSequence(cohort: Int): Mono<Long> =
		redisTemplate.opsForValue().increment(cohortOrderKey(cohort))
			.switchIfEmpty(Mono.error(AppException(ErrorCode.INTERNAL_SERVER_ERROR, "Failed to allocate user code sequence.")))

	companion object {
		private const val KEY = "user_seq"
		private fun cohortOrderKey(cohort: Int): String = "user_code_seq:cohort:$cohort"
	}
}
