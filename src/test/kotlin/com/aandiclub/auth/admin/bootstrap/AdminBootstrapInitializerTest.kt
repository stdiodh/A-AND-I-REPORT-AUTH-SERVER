package com.aandiclub.auth.admin.bootstrap

import com.aandiclub.auth.admin.config.BootstrapAdminProperties
import com.aandiclub.auth.security.service.PasswordService
import com.aandiclub.auth.user.domain.UserEntity
import com.aandiclub.auth.user.domain.UserRole
import com.aandiclub.auth.user.service.UserPublicCodeService
import com.aandiclub.auth.user.repository.UserRepository
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.springframework.boot.DefaultApplicationArguments
import reactor.core.publisher.Mono
import java.util.UUID

class AdminBootstrapInitializerTest : FunSpec({
	test("should create admin account when enabled and missing") {
		val properties = BootstrapAdminProperties(enabled = true, username = "admin", password = "Admin!Pass123")
		val userRepository = mockk<UserRepository>()
		val passwordService = mockk<PasswordService>()
		val entitySlot = slot<UserEntity>()

		every { userRepository.findByUsername("admin") } returns Mono.empty()
		every { passwordService.hash("Admin!Pass123") } returns "hashed-admin-pass"
		every { userRepository.save(capture(entitySlot)) } returns Mono.just(
			UserEntity(
				id = UUID.randomUUID(),
				username = "admin",
				passwordHash = "hashed-admin-pass",
				role = UserRole.ADMIN,
			),
		)

		val initializer = AdminBootstrapInitializer(properties, userRepository, passwordService, UserPublicCodeService())
		initializer.run(DefaultApplicationArguments())

		entitySlot.captured.username shouldBe "admin"
		entitySlot.captured.role shouldBe UserRole.ADMIN
		verify(exactly = 1) { userRepository.save(any()) }
	}

	test("should skip when password is blank") {
		val properties = BootstrapAdminProperties(enabled = true, username = "admin", password = "")
		val userRepository = mockk<UserRepository>()
		val passwordService = mockk<PasswordService>()
		val initializer = AdminBootstrapInitializer(properties, userRepository, passwordService, UserPublicCodeService())

		initializer.run(DefaultApplicationArguments())

		verify(exactly = 0) { userRepository.findByUsername(any()) }
	}
})
