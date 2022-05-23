package com.example.springsecuritydemo.auth;

import com.google.common.collect.Lists;
import org.checkerframework.checker.units.qual.A;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.springsecuritydemo.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDAO{
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers().stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    //Replace with getting from database
    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
            new ApplicationUser(
                    STUDENT.getGrantedAuthorities(),
                    passwordEncoder.encode("password"),
                    "annasmith",
                    true,
                    true,
                    true,
                    true
                    ),
                new ApplicationUser(
                    ADMIN.getGrantedAuthorities(),
                    passwordEncoder.encode("password123"),
                    "linda",
                    true,
                    true,
                    true,
                    true
                    ),
                new ApplicationUser(
                    ADMINTRAINEE.getGrantedAuthorities(),
                    passwordEncoder.encode("password123"),
                    "tom",
                    true,
                    true,
                    true,
                    true
                    )
                );
        return applicationUsers;
    }
}
