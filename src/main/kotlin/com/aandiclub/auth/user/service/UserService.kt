package com.aandiclub.auth.user.service

import com.aandiclub.auth.security.auth.AuthenticatedUser
import com.aandiclub.auth.user.web.dto.ChangePasswordRequest
import com.aandiclub.auth.user.web.dto.ChangePasswordResponse
import com.aandiclub.auth.user.web.dto.CreateProfileImageUploadUrlRequest
import com.aandiclub.auth.user.web.dto.CreateProfileImageUploadUrlResponse
import com.aandiclub.auth.user.web.dto.MeResponse
import com.aandiclub.auth.user.web.dto.UserLookupResponse
import org.springframework.http.codec.multipart.FilePart
import reactor.core.publisher.Mono

interface UserService {
	fun getMe(user: AuthenticatedUser): Mono<MeResponse>
	fun lookupByPublicCode(code: String): Mono<UserLookupResponse>
	fun updateProfile(user: AuthenticatedUser, nickname: String?, profileImage: FilePart?, profileImageUrl: String?): Mono<MeResponse>
	fun createProfileImageUploadUrl(user: AuthenticatedUser, request: CreateProfileImageUploadUrlRequest): Mono<CreateProfileImageUploadUrlResponse>
	fun changePassword(user: AuthenticatedUser, request: ChangePasswordRequest): Mono<ChangePasswordResponse>
}
