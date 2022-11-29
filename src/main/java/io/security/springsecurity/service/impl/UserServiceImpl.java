package io.security.springsecurity.service.impl;

import io.security.springsecurity.domain.entity.Account;
import io.security.springsecurity.repository.UserRepository;
import io.security.springsecurity.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service("userService")
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Transactional
    @Override
    public void createUser(Account account){
        userRepository.save(account);

    }
}
