package io.security.springsecurity.service;

import io.security.springsecurity.domain.entity.Account;

public interface UserService {
    void createUser(Account account);
}
