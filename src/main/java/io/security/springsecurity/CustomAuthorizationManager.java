package io.security.springsecurity;

import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authorization.AuthorityAuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

public class CustomAuthorizationManager<T> implements AuthorizationManager<T> {

    private static final String ROLE_PREFIX = "ROLE_";

    private final List<GrantedAuthority> authorities;

    private RoleHierarchy roleHierarchy = new NullRoleHierarchy();

    public CustomAuthorizationManager(String... authorities) {
        this.authorities = AuthorityUtils.createAuthorityList(authorities);
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, T object) {
        boolean granted = isGranted(authentication.get());
        return new AuthorityAuthorizationDecision(granted, this.authorities);
    }

    private boolean isGranted(Authentication authentication) {
        return authentication != null && authentication.isAuthenticated() && isAuthorized(authentication);
    }

    private boolean isAuthorized(Authentication authentication) {
        Set<String> authorities = AuthorityUtils.authorityListToSet(this.authorities);
        for (GrantedAuthority grantedAuthority : getGrantedAuthorities(authentication)) {
            if (authorities.contains(grantedAuthority.getAuthority())) {
                return true;
            }
        }
        return false;
    }

    private Collection<? extends GrantedAuthority> getGrantedAuthorities(Authentication authentication) {
        return this.roleHierarchy.getReachableGrantedAuthorities(authentication.getAuthorities());
    }
}
