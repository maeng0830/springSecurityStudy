package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

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
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final PrincipalOauth2UserService principalOauth2UserService;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();

		// 클라이언트 요청 주소들에 대한 접근 권한 설정
		http.authorizeRequests()
				.antMatchers("/user/**").authenticated()
				.antMatchers("/manager/**")
				.access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
				.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
				.anyRequest().permitAll()
				.and()
				.formLogin()
				.loginPage("/loginForm") // 로그인 페이지 주소 설정. 특정 권한이 필요한 주소로 접근할 때, 로그인이 안되어 있다면 로그인 페이지로 이동
				.loginProcessingUrl("/login") // 해당 주소 호출 -> 시큐리티 차원에서 로그인 진행
				.defaultSuccessUrl("/") // 로그인 성공 시 이동할 주소, but 특정 주소 요청 -> 로그인 페이지 -> 로그인 성공 -> 특정 페이지로 동작한다.
				.and()
				.oauth2Login()
				.loginPage("/loginForm")
				.userInfoEndpoint()
				.userService(principalOauth2UserService); // 구글 로그인 후 후처리가 필요함. Tip: 코드 X, 엑세스 토큰 + 사용자 프로필 O
	}
}
