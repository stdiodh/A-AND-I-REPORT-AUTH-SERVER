package com.aandiclub.auth.common.bootstrap

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.r2dbc.core.DatabaseClient
import org.springframework.stereotype.Component

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@ConditionalOnProperty(prefix = "app.schema-guard", name = ["enabled"], havingValue = "true", matchIfMissing = true)
class UserSchemaStartupGuard(
	private val databaseClient: DatabaseClient,
) : ApplicationRunner {

	override fun run(args: ApplicationArguments) {
		val existingColumns = databaseClient.sql(SCHEMA_PROBE_SQL)
			.map { row, _ -> row.get("column_name", String::class.java)?.lowercase() ?: "" }
			.all()
			.collectList()
			.map { columns -> columns.filter { it.isNotBlank() }.toSet() }
			.onErrorMap { throwable: Throwable ->
				IllegalStateException(
					"Failed to verify required users schema columns before startup.",
					throwable,
				)
			}
			.block() ?: emptySet()

		val missingColumns = missingRequiredColumns(existingColumns)
		if (missingColumns.isNotEmpty()) {
			throw IllegalStateException(
				"Database schema for table 'users' is outdated. Missing columns: ${missingColumns.joinToString(", ")}. " +
					"Apply Flyway migration V5__add_user_public_code_and_track.sql and ensure DB_JDBC_URL points to the same database as DB_R2DBC_URL.",
			)
		}
	}

	companion object {
		private val REQUIRED_COLUMNS = setOf("user_track", "cohort", "cohort_order", "public_code")
		private const val SCHEMA_PROBE_SQL = """
            SELECT LOWER(column_name) AS column_name
            FROM information_schema.columns
            WHERE LOWER(table_name) = 'users'
              AND LOWER(column_name) IN ('user_track', 'cohort', 'cohort_order', 'public_code')
        """

		internal fun missingRequiredColumns(existingColumns: Set<String>): List<String> {
			val normalizedExisting = existingColumns.map { it.lowercase() }.toSet()
			return (REQUIRED_COLUMNS - normalizedExisting).sorted()
		}
	}
}
