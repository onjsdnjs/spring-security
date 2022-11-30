package io.security.springsecurity;

import jakarta.servlet.DispatcherType;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.ArrayList;
import java.util.List;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests().shouldFilterAllDispatcherTypes(false)
                .dispatcherTypeMatchers(DispatcherType.ERROR)

//                .requestMatchers("/user").hasRole("USER")
//                .requestMatchers("/admin").hasRole("ADMIN")
        .authenticated()
                ;
        http.formLogin();
        http.addFilterAt(customAuthorizationFilter(null), AuthorizationFilter.class);
        return http.build();
    }

    @Bean
    public CustomAuthorizationFilter customAuthorizationFilter(ApplicationContext applicationContext){

        HandlerMappingIntrospector mvcHandlerMappingIntrospector =
                applicationContext.getBean("mvcHandlerMappingIntrospector", HandlerMappingIntrospector.class);

        List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings
                = new ArrayList<>();

        RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> requestMatcherEntry1 = new RequestMatcherEntry<>(new MvcRequestMatcher(mvcHandlerMappingIntrospector, "/user")
                , new CustomAuthorizationManager<>("ROLE_USER"));

        RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> requestMatcherEntry2 = new RequestMatcherEntry<>(new MvcRequestMatcher(mvcHandlerMappingIntrospector, "/admin")
                , new CustomAuthorizationManager<>("ROLE_ADMIN"));

        RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> requestMatcherEntry3 = new RequestMatcherEntry<>(AnyRequestMatcher.INSTANCE
                , new AuthenticatedAuthorizationManager<>());


        mappings.add(requestMatcherEntry1);
        mappings.add(requestMatcherEntry2);
        mappings.add(requestMatcherEntry3);

        CustomRequestMatcherDelegatingAuthorizationManager authorizationManager = new CustomRequestMatcherDelegatingAuthorizationManager(mappings);

        return new CustomAuthorizationFilter(authorizationManager);
    }
}
