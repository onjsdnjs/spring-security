package io.security.springsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.servlet.http.HttpSession;
import java.util.Arrays;

@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    SecurityFilterChain securityFilterChain1(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").access("hasRole('ADMIN')")
	            .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();

        http.formLogin()
                .loginPage("/login")
//                .defaultSuccessUrl("/home")
//                .failureUrl("/error")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/loginProc")
                /*.successHandler((request, response, authentication) -> {
                    System.out.println("authentication: " + authentication);
                    response.sendRedirect("/");
                })*/
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
//                .invalidSessionUrl("/invaild")
                .maximumSessions(10)
//                .maxSessionsPreventsLogin(false); // 이전세션 만료
                .maxSessionsPreventsLogin(true) // 동시접속 차단
                .and()
                .sessionFixation().changeSessionId()

                //SessionManagementConfigurer.init()
                //시큐리티가 세션을 생성하지 않고 사용하지 않는 것
                //CsrfFilter, HttpSessionCsrfTokenRepository
//                .sessionCreationPolicy(SessionCreationPolicy.NEVER)
                ;
        http.userDetailsService(userDetailsService());

        http.exceptionHandling()
//                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.sendRedirect("/denied");
                });

        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    @Order(0)
    SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {
        http
                .antMatcher("/api/**")
                .authorizeRequests()
                .anyRequest().authenticated();

        http.httpBasic();

        return http.build();
    }

    @Bean
    public CustomUserDetailsService customUserDetailsService(){
        return new CustomUserDetailsService();
    }

    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider(){
        return new CustomAuthenticationProvider();
    }

//    @Bean
    public UserDetailsService userDetailsService(){

        UserDetails user1 = User.withUsername("user").password(passwordEncoder().encode("1111")).roles("USER").build();
        UserDetails user2 = User.withUsername("sys").password(passwordEncoder().encode("1111")).roles("SYS").build();
        UserDetails user3 = User.withUsername("admin").password(passwordEncoder().encode("1111")).roles("ADMIN").build();

        return new InMemoryUserDetailsManager(Arrays.asList(user1,user2,user3));
    }
}
