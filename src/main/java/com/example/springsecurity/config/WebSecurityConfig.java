package com.example.springsecurity.config;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
    /**
     * Web Security Configuration
     * This class ensures that only authenticated users can access the app
     * It uses @EnableWebSecurity to enable Spring Security's web security
     * support and provide the Spring MVC integration.
     *
     * Security Filter Chain - this bean defines which URL paths should
     *                          be decured and which should not. "/" and "/home"
     *                          does not require any authentication.
     *
     * UserDetailsService - thi sbean sets up an in-memory user store with a single user.
     *                      That user is given a username of user a password of password and a role
     *                      of USER. //TODO this method should be changed in production.
     *
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http
                .authorizeHttpRequests((requests)-> requests
                        .requestMatchers("/","/home").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin((form)-> form
                        //.loginPage("/login")
                        .permitAll()
                )
                .logout((logout)->logout.permitAll());
        return http.build();

    }
    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user =
                User.withDefaultPasswordEncoder()
                        .username("user")
                        .password("password")
                        .roles("USER")
                        .build();
        return new InMemoryUserDetailsManager(user);
    }
//    @Bean
//    public static PasswordEncoder passwordEncoder(){
//        return new BCryptPasswordEncoder();
//    }
}
