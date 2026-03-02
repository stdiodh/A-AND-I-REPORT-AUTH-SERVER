package com.aandiclub.auth.user.repository

import com.aandiclub.auth.user.domain.UserEntity
import org.springframework.data.repository.reactive.ReactiveCrudRepository
import reactor.core.publisher.Mono
import java.util.UUID

interface UserRepository : ReactiveCrudRepository<UserEntity, UUID> {
	fun findByUsername(username: String): Mono<UserEntity>
	fun findByPublicCode(publicCode: String): Mono<UserEntity>
}
