package io.security.springsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;

import javax.servlet.http.HttpSession;

@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests()
//                .antMatchers("/login**").permitAll()
                .antMatchers("/invaild").permitAll()
                .anyRequest().authenticated();
        http.formLogin()
//                .loginPage("/login")
                .defaultSuccessUrl("/home")
                .failureUrl("/error")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/loginProc")
                .successHandler((request, response, authentication) -> {
                    System.out.println("authentication: " + authentication);
                    response.sendRedirect("/");
                })
                .failureHandler((request, response, exception) -> {
                    System.out.println("authentication: " + exception.getMessage());
//                    response.sendRedirect("/login?error=true");
                    response.sendRedirect("/login");
                })
                .permitAll();

        http.logout()
//                .logoutUrl("/logoutexe")
                .logoutSuccessUrl("/login")
                .deleteCookies("JSESSIONID")
                .addLogoutHandler((request, response, authentication) -> {
                    HttpSession session = request.getSession();
                    session.invalidate();
                    SecurityContext context = SecurityContextHolder.getContext();
                    SecurityContextHolder.clearContext();
                    context.setAuthentication(null);
                })
                .logoutSuccessHandler((request, response, authentication) -> {
                    System.out.println("logout is succeed");
                    response.sendRedirect("/login");
                });

        http.sessionManagement()
                .invalidSessionUrl("/invaild")
                .maximumSessions(1)
//                .maxSessionsPreventsLogin(false); // 이전세션 만료
                .maxSessionsPreventsLogin(true) // 동시접속 차단
                .and()
                .sessionFixation().changeSessionId()

                //SessionManagementConfigurer.init()
                //시큐리티가 세션을 생성하지 않고 사용하지 않는 것
                .sessionCreationPolicy(SessionCreationPolicy.NEVER)
                ;

        return http.build();
    }
}
