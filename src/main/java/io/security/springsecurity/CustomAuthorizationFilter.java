package io.security.springsecurity;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

public class CustomAuthorizationFilter extends AuthorizationFilter {

    public CustomAuthorizationFilter(AuthorizationManager<HttpServletRequest> authorizationManager) {
        super(authorizationManager);
    }
}
