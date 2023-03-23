package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class IndexController {

	private final UserRepository userRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	@GetMapping("/test/login")
	@ResponseBody
	public String loginTest(Authentication authentication,
							@AuthenticationPrincipal PrincipalDetails userDetails) {
		System.out.println("============= 일반 로그인 ===============");

		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("principalDetails.getUser() = " + principalDetails.getUser());

		// @AuthenticationPrincipal은 UserDetails 타입에 적용하여 로그인한 유저의 세션 정보를 가져올 수 있다.
		System.out.println("userDetails.getUsername() = " + userDetails.getUser());

		return "일반 로그인 세션 정보 확인";
	}

	@GetMapping("/test/oauth/login")
	@ResponseBody
	public String oauthLoginTest(Authentication authentication,
								 @AuthenticationPrincipal OAuth2User userDetails) {
		System.out.println("============= 구글 로그인 ===============");

		// PrincipalDetails 타입으로 캐스팅 불가, OAuth2User 타입으로 캐스팅 가능
		OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
		System.out.println("principalDetails.getUser() = " + oAuth2User.getAttributes());

		// @AuthenticationPrincipal은 OAuth2User 타입에 적용하여 로그인한 유저의 세션 정보를 가져올 수 있다.
		System.out.println("userDetails.getUsername() = " + userDetails.getAttributes());

		return "구글 로그인 세션 정보 확인";
	}

	@GetMapping({"", "/"})
	public String index() {
		return "index";
	}

	@GetMapping("/user")
	@ResponseBody
	public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
		System.out.println("principalDetails.getUser() = " + principalDetails.getUser());
		return "user";
	}

	@GetMapping("/admin")
	@ResponseBody
	public String admin() {
		return "admin";
	}

	@GetMapping("/manager")
	@ResponseBody
	public String manager() {
		return "manager";
	}

	// 기본적으로 스프링시큐리티가 해당 주소를 잡아서, 시큐리티 로그인 뷰를 반환
	// 스프링 시큐리티 필터를 등록한 후에는 별도로 설정한 뷰를 반환
	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}

	@GetMapping("/joinForm")
	public String joinForm() {
		return "joinForm";
	}

	@PostMapping("/join")
	public String join(User user) {
		System.out.println("user = " + user);

		user.setRole("ROLE_USER");
		user.setPassword(
				bCryptPasswordEncoder.encode(user.getPassword())); // 암호화되지 않은 비밀번호는 시큐리티로 로그인 불가능
		userRepository.save(user); // 회원 가입(데이터 저장)

		return "redirect:/loginForm";
	}

	@Secured("ROLE_ADMIN") // '/info'에 ADMIN 접근 권한을 설정한다.
	@GetMapping("/info")
	@ResponseBody
	public String info() {
		return "개인 정보";
	}

	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
	// '/data'에 ADMIN, MANAGER 접근 권한을 설정한다.
	@GetMapping("/data")
	@ResponseBody
	public String data() {
		return "데이터";
	}
}
