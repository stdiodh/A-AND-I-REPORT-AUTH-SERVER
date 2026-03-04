package com.aandiclub.auth.admin.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "app.invite-mail")
data class InviteMailProperties(
	val subject: String = "A&I 개발동아리 신규 동아리원 초대 안내",
	val from: String = "",
	val fromName: String = "A&I 개발동아리 운영진",
)
