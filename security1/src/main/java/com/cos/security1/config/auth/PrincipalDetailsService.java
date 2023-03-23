package com.cos.security1.config.auth;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * 시큐리티 설정에서 loginProcessingUrl("/login)의 주소를 요청할 때
 * UserDetailsService 타입으로 등록된 빈의 loadUserByUserName()이 호출된다.
 */
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	// 파라미터 username은 쿼리 파라미터의 값이 사용된다. 비밀번호는 UsernameAndPasswordToken 통해 내부에서 자동 검증된다.
	// 리턴된 UserDetails 객체는 Authentication 객체 내부에 저장된다.
	// Authentication(내부 UserDetails)는 시큐리티 세션에 저장된다.
	// 시큐리티 세션(SecurityContextHolder:Authentication(내부 UserDetails))
	// 메소드 종료 시 @AuthenticationPrincipal 어노테이션이 생성된다.
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Optional<User> optionalUser = userRepository.findByUsername(username);

		return optionalUser.map(PrincipalDetails::new).orElse(null);
	}
}
