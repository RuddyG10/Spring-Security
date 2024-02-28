package com.example.springsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;

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
                        .requestMatchers("/","/home").permitAll() //These routes will not need authentication
                        .anyRequest().authenticated() //any other HTTP request, you will need to authenticate
                )
                .csrf((Customizer.withDefaults())) //enables csrf security, its important if
                //the app has users that can log in. This is the default configuration
                .formLogin((form)-> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/hello")
                        .permitAll()
                        .failureHandler(authenticationFailureHandler())
                )
                .logout((logout)->logout
                        .logoutSuccessUrl("/")
                        .deleteCookies("JSESSIONID")
                        .invalidateHttpSession(true)
                        .permitAll())
                .rememberMe((remember)->remember
                        .rememberMeParameter("remember-me")
                        .key("uniqueAndSecretKey")
                        .tokenValiditySeconds(1000)
                        .rememberMeCookieName("rememberloginnardone")
                        .rememberMeParameter("remember-me"))
                .sessionManagement((session)->session //This part create always 1 session in the app
                        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                        .maximumSessions(1));


        return http.build();

    }
    @Bean
    public UserDetailsService userDetailsService(){
        InMemoryUserDetailsManager inMemoryUserDetailsManager = new InMemoryUserDetailsManager();
        inMemoryUserDetailsManager.createUser(User.withUsername("admin").password(passwordEncoder().encode("adminpassw")).roles("ADMIN").build());



//        UserDetails user =
//                User.withDefaultPasswordEncoder()
//                        .username("user")
//                        .password("password")
//                        .roles("USER")
//                        .build();
        return inMemoryUserDetailsManager;
    }
    @Bean
    public static PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler(){
        return new CustomAuthenticationFailureHandler();
    }
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher(){
        return new HttpSessionEventPublisher();
    }




}
