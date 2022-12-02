package io.security.springsecurity;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Autowired
    private ApplicationContext applicationContext;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,AuthorizationManager<RequestAuthorizationContext> access) throws Exception {
        http.authorizeHttpRequests().anyRequest().access(access)
//                .requestMatchers("/user").hasRole("USER")
//                .requestMatchers("/admin").hasRole("ADMIN")
//                .anyRequest().authenticated();
                ;
        http.formLogin();
//        http.addFilterAt(customAuthorizationFilter(), AuthorizationFilter.class);
        return http.build();
    }

    /*@Bean
    public CustomAuthorizationFilter customAuthorizationFilter(){

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
    }*/

    /*@Bean
    public AuthorizationManager<RequestAuthorizationContext> authorizationManager(){

        HandlerMappingIntrospector mvcHandlerMappingIntrospector = applicationContext.getBean("mvcHandlerMappingIntrospector", HandlerMappingIntrospector.class);

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

        return new CustomRequestMatcherDelegatingAuthorizationManager(mappings);
    }*/

    @Bean
    AuthorizationManager<RequestAuthorizationContext> requestMatcherAuthorizationManager(HandlerMappingIntrospector introspector) {
        MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);
        RequestMatcher permitAll =
                new AndRequestMatcher(
                        mvcMatcherBuilder.pattern("/resources/**"),
                        mvcMatcherBuilder.pattern("/signup"),
                        mvcMatcherBuilder.pattern("/about"));
        RequestMatcher admin = mvcMatcherBuilder.pattern("/admin/**");
        RequestMatcher db = mvcMatcherBuilder.pattern("/db/**");
        RequestMatcher any = AnyRequestMatcher.INSTANCE;
        AuthorizationManager<HttpServletRequest> manager = RequestMatcherDelegatingAuthorizationManager.builder()
                .add(permitAll, (authentication,object) -> new AuthorizationDecision(true))
                .add(admin, AuthorityAuthorizationManager.hasRole("ADMIN"))
                .add(db, AuthorityAuthorizationManager.hasRole("DBA"))
                .add(any, new AuthenticatedAuthorizationManager<>())
                .build();
        return (authentication, context) -> manager.check(authentication,context.getRequest());
    }
}
