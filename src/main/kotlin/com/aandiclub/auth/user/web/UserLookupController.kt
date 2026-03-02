package com.aandiclub.auth.user.web

import com.aandiclub.auth.common.api.ApiResponse
import com.aandiclub.auth.user.service.UserService
import com.aandiclub.auth.user.web.dto.UserLookupResponse
import jakarta.validation.constraints.NotBlank
import org.springframework.validation.annotation.Validated
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import reactor.core.publisher.Mono

@RestController
@RequestMapping("/v1/users")
@Validated
class UserLookupController(
	private val userService: UserService,
) {
	@GetMapping("/lookup")
	fun lookupByPublicCode(
		@RequestParam("code")
		@NotBlank(message = "code is required")
		code: String,
	): Mono<ApiResponse<UserLookupResponse>> =
		userService.lookupByPublicCode(code).map { ApiResponse.success(it) }
}
