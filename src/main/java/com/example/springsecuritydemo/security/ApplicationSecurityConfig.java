package com.example.springsecuritydemo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.example.springsecuritydemo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                /*  Cross Site Request Forgery
                    Disable this only on non-brousers clients, like APIs */
                .csrf().disable()
                .authorizeRequests()
                /*  Equivalent of @PreAuthorize. For example:
                    .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                    .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSES_WRITE.getPermission())
                */
                .antMatchers("/", "index","/css/*", "/js/*").permitAll()
                // First mather has higher priority than others.
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                    .loginPage("/login")
                    .permitAll()
                    .defaultSuccessUrl("/courses", true)
                    // 'password', 'username' and 'remember-id' - names of <input> in html templates
                    .passwordParameter("password")
                    .usernameParameter("username")
                .and()
                .rememberMe()
                    .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21)) // Defaults for 2 weeks
                    .key("somethingverysecured")
                    .rememberMeParameter("remember-me")
                .and()
                .logout()
                    .logoutUrl("/logout")
                    // If csrf enabled(default), you should delete this line
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID", "remember-me")
                    .logoutSuccessUrl("/login");
    }

    @Bean
    protected UserDetailsService userDetailsService() {
         UserDetails annaSmithUser = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password"))
                 .authorities(STUDENT.getGrantedAuthorities())
//                .roles(STUDENT.name()) // ROLE_STUDENT
                .build();
         UserDetails lindaUser = User.builder()
                 .username("linda")
                 .password(passwordEncoder.encode("password123"))
//                 .roles(ADMIN.name()) // ROLE_ADMIN
                 .authorities(ADMIN.getGrantedAuthorities())
                 .build();
         UserDetails tomUser = User.builder()
                 .username("tom")
                 .password(passwordEncoder.encode("password123"))
//                 .roles(ADMINTRAINEE.name()) // ROLE_ADMIN
                 .authorities(ADMINTRAINEE.getGrantedAuthorities())
                 .build();

         return new InMemoryUserDetailsManager(
                 annaSmithUser,
                 lindaUser,
                 tomUser
         );
    }
}
