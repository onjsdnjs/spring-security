package io.security.springsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.Map;

@Repository
public class UserRepository implements ApplicationRunner {

    @Autowired
    private PasswordEncoder passwordEncoder;

    private Map<String,Object> users;
    public UserDetails findByUsername(String username){
        if(users.containsKey(username)){
            return (UserDetails)users.get(username);
        }
        return null;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        users = new HashMap<>();
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder.encode("1111"))
                .authorities(AuthorityUtils.createAuthorityList("ROLE_USER"))
                .build();

        users.put("user",user);
    }
}
