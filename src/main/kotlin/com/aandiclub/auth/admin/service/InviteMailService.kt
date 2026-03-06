package com.aandiclub.auth.admin.service

import com.aandiclub.auth.admin.config.InviteMailProperties
import com.aandiclub.auth.common.error.AppException
import com.aandiclub.auth.common.error.ErrorCode
import com.aandiclub.auth.user.domain.UserRole
import jakarta.mail.internet.InternetAddress
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Value
import org.springframework.mail.javamail.JavaMailSender
import org.springframework.mail.javamail.MimeMessageHelper
import org.springframework.stereotype.Service
import org.thymeleaf.context.Context
import org.thymeleaf.spring6.SpringTemplateEngine
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers
import java.nio.charset.StandardCharsets
import java.time.Instant

@Service
class InviteMailService(
	private val mailSenderProvider: ObjectProvider<JavaMailSender>,
	private val templateEngine: SpringTemplateEngine,
	private val inviteMailProperties: InviteMailProperties,
	@Value("\${spring.mail.username:}") private val smtpUsername: String,
) {
	fun sendInviteMail(
		toEmail: String,
		username: String,
		role: UserRole,
		inviteUrl: String,
		expiresAt: Instant,
		userTrack: String,
		cohort: Int,
		cohortOrder: Int,
		publicCode: String?,
	): Mono<Void> =
		Mono.fromCallable {
			val mailSender = mailSenderProvider.ifAvailable
				?: throw AppException(ErrorCode.INTERNAL_SERVER_ERROR, MAIL_SENDER_NOT_CONFIGURED_MESSAGE)
			val message = mailSender.createMimeMessage()
			val helper = MimeMessageHelper(message, StandardCharsets.UTF_8.name())
			helper.setTo(toEmail)
			helper.setFrom(
				InternetAddress(
					resolveFromAddress(),
					inviteMailProperties.fromName,
					StandardCharsets.UTF_8.name(),
				),
			)
			helper.setSubject(inviteMailProperties.subject)
			helper.setText(
				renderInviteHtml(
					username = username,
					role = role,
					inviteUrl = inviteUrl,
					expiresAt = expiresAt,
					userTrack = userTrack,
					cohort = cohort,
					cohortOrder = cohortOrder,
					publicCode = publicCode,
				),
				true,
			)
			mailSender.send(message)
			Unit
		}
			.subscribeOn(Schedulers.boundedElastic())
			.onErrorMap {
				if (it is AppException) {
					it
				} else {
					AppException(ErrorCode.INTERNAL_SERVER_ERROR, INVITE_MAIL_SEND_FAILED_MESSAGE)
				}
			}
			.then()

	private fun resolveFromAddress(): String {
		val configuredFrom = inviteMailProperties.from.trim()
		if (configuredFrom.isNotEmpty()) {
			return configuredFrom
		}
		val normalizedSmtpUsername = smtpUsername.trim()
		if (normalizedSmtpUsername.isNotEmpty()) {
			return normalizedSmtpUsername
		}
		throw AppException(ErrorCode.INTERNAL_SERVER_ERROR, MAIL_FROM_NOT_CONFIGURED_MESSAGE)
	}

	private fun renderInviteHtml(
		username: String,
		role: UserRole,
		inviteUrl: String,
		expiresAt: Instant,
		userTrack: String,
		cohort: Int,
		cohortOrder: Int,
		publicCode: String?,
	): String {
		val context = Context()
		context.setVariable("username", username)
		context.setVariable("role", role.name)
		context.setVariable("inviteUrl", inviteUrl)
		context.setVariable("expiresAt", expiresAt.toString())
		context.setVariable("userTrack", if (userTrack == "NO") "미설정" else userTrack)
		context.setVariable("cohort", if (cohort == 0) "미설정" else "${cohort}기")
		context.setVariable("cohortOrder", if (cohortOrder == 0) "미설정" else "${cohortOrder}번")
		context.setVariable("publicCode", publicCode ?: "-")
		return templateEngine.process(TEMPLATE_NAME, context)
	}

	companion object {
		private const val TEMPLATE_NAME = "invite-mail"
		private const val INVITE_MAIL_SEND_FAILED_MESSAGE = "Failed to send invite email."
		private const val MAIL_SENDER_NOT_CONFIGURED_MESSAGE = "Mail sender is not configured."
		private const val MAIL_FROM_NOT_CONFIGURED_MESSAGE = "Mail from address is not configured."
	}
}
