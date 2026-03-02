package com.aandiclub.auth.admin.sequence

import reactor.core.publisher.Mono

interface UsernameSequenceService {
	fun nextSequence(): Mono<Long>
	fun nextCohortOrderSequence(cohort: Int): Mono<Long>
}
