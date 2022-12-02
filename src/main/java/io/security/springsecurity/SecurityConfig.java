package io.security.springsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .requestMatchers("/user").hasRole("USER")
                .requestMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated();
                ;
//        http.securityContext(securityContext -> securityContext.requireExplicitSave(true));
        http.securityContext(httpSecuritySecurityContextConfigurer ->
                httpSecuritySecurityContextConfigurer.securityContextRepository(new RequestAttributeSecurityContextRepository()));
        http.formLogin();
        return http.build();
    }
}
