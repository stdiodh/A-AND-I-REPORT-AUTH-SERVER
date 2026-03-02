package com.aandiclub.auth.security.config

import com.aandiclub.auth.admin.config.BootstrapAdminProperties
import com.aandiclub.auth.admin.config.InviteMailProperties
import com.aandiclub.auth.admin.config.InviteProperties
import com.aandiclub.auth.security.auth.JwtReactiveAuthenticationManager
import com.aandiclub.auth.security.filter.BearerTokenAuthenticationConverter
import com.aandiclub.auth.security.jwt.JwtProperties
import com.aandiclub.auth.user.config.ProfileImageProperties
import com.aandiclub.auth.user.config.ProfileProperties
import com.aandiclub.auth.user.config.UserProfileEventProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsConfigurationSource
import org.springframework.web.cors.reactive.CorsWebFilter
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource

@Configuration
@EnableWebFluxSecurity
@EnableConfigurationProperties(
	JwtProperties::class,
	BootstrapAdminProperties::class,
	AppCorsProperties::class,
	InviteProperties::class,
	InviteMailProperties::class,
	ProfileProperties::class,
	ProfileImageProperties::class,
	UserProfileEventProperties::class,
)
class SecurityConfig {

	@Bean
	fun corsConfigurationSource(corsProperties: AppCorsProperties): CorsConfigurationSource {
		val configuration = CorsConfiguration().apply {
			allowedOrigins = corsProperties.allowedOriginsList()
			allowedMethods = corsProperties.allowedMethodsList()
			allowedHeaders = corsProperties.allowedHeadersList()
			exposedHeaders = corsProperties.exposedHeadersList()
			allowCredentials = corsProperties.allowCredentials
			maxAge = corsProperties.maxAgeSeconds
		}
		return UrlBasedCorsConfigurationSource().apply {
			registerCorsConfiguration("/**", configuration)
		}
	}

	@Bean
	fun corsWebFilter(corsConfigurationSource: CorsConfigurationSource): CorsWebFilter =
		CorsWebFilter(corsConfigurationSource)

	@Bean
	fun securityWebFilterChain(
		http: ServerHttpSecurity,
		jwtReactiveAuthenticationManager: JwtReactiveAuthenticationManager,
		corsConfigurationSource: CorsConfigurationSource,
	): SecurityWebFilterChain {
		val jwtAuthenticationWebFilter = AuthenticationWebFilter(jwtReactiveAuthenticationManager).apply {
			setServerAuthenticationConverter(BearerTokenAuthenticationConverter())
		}

		return http
			.cors { it.configurationSource(corsConfigurationSource) }
			.csrf { it.disable() }
			.formLogin { it.disable() }
			.httpBasic { it.disable() }
			.exceptionHandling {
				it.authenticationEntryPoint(HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED))
				it.accessDeniedHandler(HttpStatusServerAccessDeniedHandler(HttpStatus.FORBIDDEN))
			}
			.authorizeExchange {
				it.pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
				it.pathMatchers(
					"/v1/auth/**",
					"/activate",
					"/api/ping/**",
					"/v3/api-docs/**",
					"/swagger-ui.html",
					"/swagger-ui/**",
					"/actuator/health",
					"/actuator/info",
				).permitAll()
				it.pathMatchers("/v1/me", "/v1/me/**").hasAnyRole("USER", "ORGANIZER", "ADMIN")
				it.pathMatchers(HttpMethod.GET, "/v1/users/lookup").hasAnyRole("ORGANIZER", "ADMIN")
				it.pathMatchers("/v1/admin/**").hasRole("ADMIN")
				it.anyExchange().authenticated()
			}
			.addFilterAt(jwtAuthenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)
			.build()
	}
}
