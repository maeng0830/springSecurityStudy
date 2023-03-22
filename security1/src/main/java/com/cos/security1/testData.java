package com.cos.security1;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class testData {

	private final UserRepository userRepository;
	private final BCryptPasswordEncoder encoder;

	@EventListener(ApplicationReadyEvent.class)
	public void initData() {
		User user = new User();
		user.setUsername("user");
		user.setPassword(encoder.encode("123"));
		user.setEmail("user@naver.com");
		user.setRole("ROLE_USER");

		User manager = new User();
		manager.setUsername("manager");
		manager.setPassword(encoder.encode("123"));
		manager.setEmail("manager@naver.com");
		manager.setRole("ROLE_MANAGER");

		User admin = new User();
		admin.setUsername("admin");
		admin.setPassword(encoder.encode("123"));
		admin.setEmail("admin@naver.com");
		admin.setRole("ROLE_ADMIN");

		userRepository.save(user);
		userRepository.save(manager);
		userRepository.save(admin);
	}
}
