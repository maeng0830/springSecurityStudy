package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.FacebookUserInfo;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.NaverUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

// PrincipalOauth2UserService, PrincipalDetailsService을 생성하는 이유는 아래와 같다.
// 두 클래스를 생성해서 loadUser()를 오버라이딩하지 않더라도 정상적으로 로그인이 된다.
// 두 클래스를 생성하는 이유는 Authentication에 저장할 객체를 PrincipalDetails로 리턴하기 위함이다.
@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	private final UserRepository userRepository;

	// 구글 로그인(Oauth2)을 통해 받은 userRequest 데이터에 대한 후처리 메소드
	// 메소드 종료 시 @AuthenticationPrincipal 어노테이션이 생성된다.
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		System.out.println(
				"userRequest.getAccessToken().getTokenValue() = " + userRequest.getAccessToken()
						.getTokenValue());
		System.out.println("userRequest.getClientRegistration().getRegistrationId() = "
				+ userRequest.getClientRegistration().getRegistrationId()); // oauth 종류 확인 가능

		// 구글 로그인 버튼 클릭 -> 구글 로그인창 -> 로그인을 완료 -> 리턴되는 code를 oauth2-client 라이브러리가 받음
		// oauth2-client 라이브러리는 code를 통해 AccessToken을 요청 -> userRequest 정보를 받게된다.
		// userRequset 정보를 사용하여 loadUser() 호출 -> 구글로부터 회원 프로필 획득
		OAuth2User oAuth2User = super.loadUser(userRequest);
		System.out.println("oAuth2User.getAttributes() = " + oAuth2User.getAttributes());

		OAuth2UserInfo oAuth2UserInfo = null;
		if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
			System.out.println("구글 로그인 요청");
			oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
		} else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
			System.out.println("페이스북 로그인 요청");
			oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
		} else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
			System.out.println("네이버 로그인 요청");
			oAuth2UserInfo = new NaverUserInfo((Map<String, Object>) oAuth2User.getAttributes().get("response"));
		} else {
			System.out.println("OAuth2는 구글, 페이스북, 네이버를 지원하고 있습니다.");
		}

		String provider = oAuth2UserInfo.getProvider();
		String providerId = oAuth2UserInfo.getProviderId(); // Oauth primaryKey
		String username = provider + "_" + providerId; // google_Oauth primaryKey
		String password = bCryptPasswordEncoder.encode("123");
		String email = oAuth2UserInfo.getEmail();
		String role = "ROLE_USER";

		User user = User.builder()
				.provider(provider)
				.providerId(providerId)
				.username(username)
				.password(password)
				.email(email)
				.role(role).build();

		// 구글 로그인 회원 가입
		userRepository.findByUsername(username).orElse(userRepository.save(user));

		// Authentication 객체에 저장된다.
		return new PrincipalDetails(user, oAuth2User.getAttributes());
	}
}
