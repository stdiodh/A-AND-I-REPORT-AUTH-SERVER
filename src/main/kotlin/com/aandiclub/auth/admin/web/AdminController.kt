package com.aandiclub.auth.admin.web

import com.aandiclub.auth.admin.service.AdminService
import com.aandiclub.auth.admin.web.dto.AdminUserSummary
import com.aandiclub.auth.admin.web.dto.CreateAdminUserRequest
import com.aandiclub.auth.admin.web.dto.CreateAdminUserResponse
import com.aandiclub.auth.admin.web.dto.DeleteUserRequest
import com.aandiclub.auth.admin.web.dto.InviteMailRequest
import com.aandiclub.auth.admin.web.dto.InviteMailResponse
import com.aandiclub.auth.admin.web.dto.ResetPasswordResponse
import com.aandiclub.auth.admin.web.dto.UpdateUserRoleRequest
import com.aandiclub.auth.admin.web.dto.UpdateUserRoleResponse
import com.aandiclub.auth.common.api.ApiResponse
import com.aandiclub.auth.security.auth.AuthenticatedUser
import jakarta.validation.Valid
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PatchMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import reactor.core.publisher.Mono
import java.util.UUID

@RestController
@RequestMapping("/v1/admin")
class AdminController(
	private val adminService: AdminService,
) {
	@GetMapping("/ping")
	fun ping(): ApiResponse<Map<String, Boolean>> = ApiResponse.success(mapOf("ok" to true))

	@GetMapping("/users")
	fun getUsers(): Mono<ApiResponse<List<AdminUserSummary>>> =
		adminService.getUsers().map { ApiResponse.success(it) }

	@PostMapping("/users")
	fun createUser(@Valid @RequestBody request: CreateAdminUserRequest): Mono<ApiResponse<CreateAdminUserResponse>> =
		adminService.createUser(request).map { ApiResponse.success(it) }

	@PostMapping("/invite-mail")
	fun sendInviteMail(@Valid @RequestBody request: InviteMailRequest): Mono<ApiResponse<InviteMailResponse>> =
		adminService.sendInviteMail(request).map { ApiResponse.success(it) }

	@PostMapping("/users/{id}/reset-password")
	fun resetPassword(@PathVariable id: UUID): Mono<ApiResponse<ResetPasswordResponse>> =
		adminService.resetPassword(id).map { ApiResponse.success(it) }

	@PatchMapping("/users/role")
	fun updateUserRole(
		@Valid @RequestBody request: UpdateUserRoleRequest,
		@AuthenticationPrincipal actor: AuthenticatedUser,
	): Mono<ApiResponse<UpdateUserRoleResponse>> =
		adminService.updateUserRole(
			targetUserId = request.userId,
			role = request.role,
			userTrack = request.userTrack,
			actorUserId = actor.userId,
		).map { ApiResponse.success(it) }

	@DeleteMapping("/users")
	fun deleteUser(
		@Valid @RequestBody request: DeleteUserRequest,
		@AuthenticationPrincipal actor: AuthenticatedUser,
	): Mono<ResponseEntity<Void>> =
		adminService.deleteUser(targetUserId = request.userId, actorUserId = actor.userId)
			.thenReturn(ResponseEntity.noContent().build())
}
