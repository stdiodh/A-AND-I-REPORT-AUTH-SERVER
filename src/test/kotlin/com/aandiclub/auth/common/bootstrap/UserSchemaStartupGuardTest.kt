package com.aandiclub.auth.common.bootstrap

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class UserSchemaStartupGuardTest {

	@Test
	fun `missingRequiredColumns returns empty when all required columns exist`() {
		val missing = UserSchemaStartupGuard.missingRequiredColumns(
			setOf("user_track", "cohort", "cohort_order", "public_code"),
		)

		assertEquals(emptyList<String>(), missing)
	}

	@Test
	fun `missingRequiredColumns returns sorted missing column list`() {
		val missing = UserSchemaStartupGuard.missingRequiredColumns(setOf("cohort", "PUBLIC_CODE"))

		assertEquals(listOf("cohort_order", "user_track"), missing)
	}
}
