package com.aandiclub.auth.admin.sequence

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import org.springframework.data.redis.core.ReactiveStringRedisTemplate
import org.springframework.data.redis.core.ReactiveValueOperations
import reactor.core.publisher.Mono
import reactor.test.StepVerifier

class RedisUsernameSequenceServiceTest : FunSpec({
	test("nextSequence should use redis INCR key user_seq") {
		val redisTemplate = mockk<ReactiveStringRedisTemplate>()
		val valueOperations = mockk<ReactiveValueOperations<String, String>>()
		every { redisTemplate.opsForValue() } returns valueOperations
		every { valueOperations.increment("user_seq") } returns Mono.just(7)

		val service = RedisUsernameSequenceService(redisTemplate)

		StepVerifier.create(service.nextSequence())
			.assertNext { next ->
				next shouldBe 7
			}
			.verifyComplete()
	}

	test("nextCohortOrderSequence should use cohort key") {
		val redisTemplate = mockk<ReactiveStringRedisTemplate>()
		val valueOperations = mockk<ReactiveValueOperations<String, String>>()
		every { redisTemplate.opsForValue() } returns valueOperations
		every { valueOperations.increment("user_code_seq:cohort:4") } returns Mono.just(11)

		val service = RedisUsernameSequenceService(redisTemplate)

		StepVerifier.create(service.nextCohortOrderSequence(4))
			.assertNext { next ->
				next shouldBe 11
			}
			.verifyComplete()
	}
})
