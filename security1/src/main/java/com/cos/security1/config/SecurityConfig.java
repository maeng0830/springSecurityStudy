package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.SecurityFilterChain;

/**
 * oauth2
 * 1. 코드 받기(인증)
 * 2. 엑세스 토큰(권한)
 * 3. 사용자 프로필 정보를 가져옴.
 * 4. 그 정보를 토대로 회원가입을 자동으로 진행 or 추가 정보가 필요하면 별도 회원 가입 진행
 */
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity // 스프링 시큐리티 필터(SecurityConfig)를 스프링 필터체인에 등록한다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // 컨트롤러 메소드에 @Secured, @PreAUthorize를 사용하여 개별적으로 접근 권한을 부여할 수 있다.
public class SecurityConfig {

	private final PrincipalOauth2UserService principalOauth2UserService;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.authorizeRequests()
				.antMatchers("/user/**").authenticated()
				.antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
				.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
				.anyRequest().permitAll()
				.and()
				.formLogin()
				.loginPage("/loginForm")
				.loginProcessingUrl("/login")
				.defaultSuccessUrl("/")
				.and()
				.oauth2Login()
				.loginPage("/loginForm")
				.userInfoEndpoint()
				.userService(principalOauth2UserService);

		return http.build();
	}
}
