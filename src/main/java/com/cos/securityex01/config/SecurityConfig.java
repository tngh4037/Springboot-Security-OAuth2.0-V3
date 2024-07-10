package com.cos.securityex01.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.cos.securityex01.config.oauth.PrincipalOauth2UserService;

@Configuration // IoC 빈(bean)을 등록
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 됩니다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secure 어노테이션 활성화, PreAuthorize/PostAuthorize 어노테이션 활성화
public class SecurityConfig {

	@Autowired
	private PrincipalOauth2UserService principalOauth2UserService;

	@Bean // 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.authorizeRequests()
				.antMatchers("/user/**").authenticated()
				//.antMatchers("/manager/**").access("hasRole('ROLE_MANAGER') and hasRole('ROLE_ADMIN')")
				//.antMatchers("/manager/**").access("hasRole('ROLE_MANAGER')")
				.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
				.anyRequest().permitAll()
				.and()
				.formLogin()
				.loginPage("/login") // 인증되지 않은 사용자가 인증이 필요한 경로로 접근시 해당 로그인 경로로 이동
				.loginProcessingUrl("/loginProc") // /loginProc 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인 처리를 진행해준다. (따라서 컨트롤러에 메서드 만들지 않아도 됨.) ( 그리고 이때 추가적으로 해줘야할 작업들이 있다. -> auth 패키지 )
				.defaultSuccessUrl("/") // 참고) loginPage("/login") 를 직접 요청해서 로그인에 성공했으면 "/" 로 이동한다. (단, 비로그인 상태에서 인증이 필요한 어떤 특정 페이지를 요청했고, 거기서 로그인 페이지로 리다이렉트 된 후 로그인했다면, "/"가 아닌, 이전에 요청했던 페이지로 이동시킨다. )
				.and()
				.oauth2Login()
				.loginPage("/login")
				.userInfoEndpoint()
				.userService(principalOauth2UserService); // 소셜 로그인이 완료된 뒤의 후처리

		return http.build();
	}
}

// 참고) 스프링 시큐리티 디폴트 로그아웃 경로: /logout

// ====================================================================================
//
// [ OAuth ]
// 1. 코드받기(인증)
// 2. 엑세스토큰(권한)
// 3. 사용자 프로필 정보를 가져온다.
// 4-1) 그 정보를 토대로 회원가입을 자동으로 진행시키기도 하고, 혹은
// 4-2) 그 정보가 부족하다면, 회원가입 창이 나타나서 추가적인 정보를 요청받도록 한다.
// 참고) 강의에서는 4-1로 한다.
//
// 참고) 구글 로그인은, 로그인이 완료되면 코드를 받지 않고, (엑세스 토큰 + 사용자 프로필 정보)를 한방에 받는다.
// ====================================================================================
//
