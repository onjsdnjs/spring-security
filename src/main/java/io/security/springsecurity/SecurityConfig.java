package io.security.springsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated();
        http.formLogin()
                .loginPage("/login")			// 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/home")				// 로그인 성공 후 이동 페이지
                .failureUrl("/error")		              // 로그인 실패 후 이동 페이지
                .usernameParameter("userId")			// 아이디 파라미터명 설정
                .passwordParameter("passwd")			// 패스워드 파라미터명 설정
                .loginProcessingUrl("/loginProc")			              // 로그인 Form Action Url
                .successHandler((request, response, authentication) -> {
                    System.out.println("authentication: " + authentication);
                })		// 로그인 성공 후 핸들러
                .failureHandler((request, response, exception) -> {
                    System.out.println("authentication: " + exception.getMessage());
                })
                .permitAll();

        return http.build();
    }
}
