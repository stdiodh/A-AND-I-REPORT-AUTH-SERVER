package com.aandiclub.auth.admin.bootstrap

import com.aandiclub.auth.admin.config.BootstrapAdminProperties
import com.aandiclub.auth.security.service.PasswordService
import com.aandiclub.auth.user.domain.UserEntity
import com.aandiclub.auth.user.domain.UserRole
import com.aandiclub.auth.user.domain.UserTrack
import com.aandiclub.auth.user.repository.UserRepository
import com.aandiclub.auth.user.service.UserPublicCodeService
import org.slf4j.LoggerFactory
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component
class AdminBootstrapInitializer(
	private val properties: BootstrapAdminProperties,
	private val userRepository: UserRepository,
	private val passwordService: PasswordService,
	private val userPublicCodeService: UserPublicCodeService,
) : ApplicationRunner {

	override fun run(args: ApplicationArguments) {
		if (!properties.enabled) {
			return
		}
		if (properties.password.isBlank()) {
			logger.warn("Bootstrap admin password is not set. Skipping admin auto-creation.")
			return
		}

		userRepository.findByUsername(properties.username)
			.switchIfEmpty(
				Mono.defer {
					val hashed = passwordService.hash(properties.password)
					userRepository.save(
						UserEntity(
							username = properties.username,
							passwordHash = hashed,
							role = UserRole.ADMIN,
							userTrack = UserTrack.NO,
							cohort = 0,
							cohortOrder = 1,
							publicCode = userPublicCodeService.generate(UserRole.ADMIN, UserTrack.NO, 0, 1),
						),
					)
				},
			)
			.block()
	}

	companion object {
		private val logger = LoggerFactory.getLogger(AdminBootstrapInitializer::class.java)
	}
}
