package com.cos.security1.config.auth;

import com.cos.security1.model.User;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import lombok.Getter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * 시큐리티가 '/login' 주소 요청을 낚아채서 로그인을 진행한다.
 * 로그인 진행이 완료되면 시큐리티 세션(SecurityContextHolder:Authentication 객체)을 만들어준다.
 * Authentication 내부에 user 정보(UserDetails 객체)가 있어야 한다.
 * UserDetails는 인터페이스이기 때문에 구현체(PrincipalDetails)가 필요하다.
 */
@Getter
@ToString
public class PrincipalDetails implements UserDetails, OAuth2User {

	private User user;
	private Map<String, Object> attributes;

	// 일반 로그인
	public PrincipalDetails(User user) {
		this.user = user;
	}

	// OAuth2 로그인
	public PrincipalDetails(User user, Map<String, Object> attributes) {
		this.user = user;
		this.attributes = attributes;
	}

	// 해당 user의 권한(user.getRole())을 리턴
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Collection<GrantedAuthority> collect = new ArrayList<>();
		collect.add(new GrantedAuthority() {
			@Override
			public String getAuthority() {
				return user.getRole();
			}
		});
		return collect;
	}

	// 비밀번호 리턴
	@Override
	public String getPassword() {
		return user.getPassword();
	}

	// 아이디 리턴
	@Override
	public String getUsername() {
		return user.getUsername();
	}

	// 만료
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	// 정지
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	// 비밀번호 기간 만료
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	// 활성화
	@Override
	public boolean isEnabled() {
		return true;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return attributes;
	}

	@Override
	public String getName() {
		return String.valueOf(attributes.get("sub"));
	}
}
