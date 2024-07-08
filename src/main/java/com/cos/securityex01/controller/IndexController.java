package com.cos.securityex01.controller;

import java.util.Iterator;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.securityex01.config.auth.PrincipalDetails;
import com.cos.securityex01.model.User;
import com.cos.securityex01.repository.UserRepository;

@Controller // View 를 리턴하겠다.
public class IndexController {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@GetMapping({ "", "/" })
	public @ResponseBody String index() {
		return "인덱스 페이지입니다.";
	}

	@GetMapping("/user")
	public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principal) {
		System.out.println("Principal : " + principal);
		System.out.println("OAuth2 : "+principal.getUser().getProvider());
		// iterator 순차 출력 해보기
		Iterator<? extends GrantedAuthority> iter = principal.getAuthorities().iterator();
		while (iter.hasNext()) {
			GrantedAuthority auth = iter.next();
			System.out.println(auth.getAuthority());
		}

		return "유저 페이지입니다.";
	}

	@GetMapping("/admin")
	public @ResponseBody String admin() {
		return "어드민 페이지입니다.";
	}
	
	//@PostAuthorize("hasRole('ROLE_MANAGER')")
	//@PreAuthorize("hasRole('ROLE_MANAGER')")
	@Secured("ROLE_MANAGER")
	@GetMapping("/manager")
	public @ResponseBody String manager() {
		return "매니저 페이지입니다.";
	}

	@GetMapping("/login")
	public String login() {
		return "login";
	}

	@GetMapping("/join")
	public String join() {
		return "join";
	}

	@PostMapping("/joinProc")
	public String joinProc(User user) {
		System.out.println("회원가입 진행 : " + user);
		String rawPassword = user.getPassword();
		String encPassword = bCryptPasswordEncoder.encode(rawPassword); // 패스워드를 암호화 하지 않으면 시큐리티로 로그인을 할 수 없음.
		user.setPassword(encPassword);
		user.setRole("ROLE_USER");
		userRepository.save(user);
		return "redirect:/";
	}

	@Secured("ROLE_ADMIN") // 특정 메서드에서 간단하게 인가처리 하고 싶은 경우 사용하면 좋을 것 같다.
	@GetMapping("info")
	public @ResponseBody String info() {
		return "개인정보";
	}

	@PreAuthorize("hasRole('ROLE_ADMIN')") // 참고1) data() 메서드가 실행되기 직전에 실행된다. 참고2) @PreAuthorize(..) : .. 에는 "ROLE_ADMIN" 과 같이 적지 못한다. "hasRole('ROLE_ADMIN')" 과 같이 적어야 한다.
	// @PostAuthorize("hasRole('ROLE_ADMIN')") // data() 메서드가 종료되고 난 뒤에 실행된다. ( 참고로 @PostAuthorize 를 쓸일은 별로 없다. )
	@GetMapping("data")
	public @ResponseBody String data() {
		return "데이터정보";
	}

}

// 참고)
// - @Secured는 표현식을 사용할 수 없다.
// - @PreAuthroize, @PostAuthorize는 표현식 사용을 사용하여 디테일한 설정이 가능하다.
// : 간단한 인가에 대한 처리의 경우는 @Secure 를 사용하고, 복잡한 인가에 대한 처리는 @Pre/PostAuthorize 를 사용하는 게 나을 것 같다.