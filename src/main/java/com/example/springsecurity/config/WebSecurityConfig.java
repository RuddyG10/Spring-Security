package com.example.springsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;

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
     * JdbcDaoImpl - implements UserDetailsService to support username-password-based authentication
     *               that is retrieved using JDBC.
     *
     * JdbcUserDetailsManager - extends JdbcDaoImpl to provide management of UserDetails through the
     *                          UserDetailsManager interface.
     * dataSource - before configuring JdbcUserDetailsManager we need to create a DataSource. Here we initialize
     *              with the default user schema via EmbeddedDatabase datasource bean created to build a new H2 database
     *              (in this case named securitydb) using the preconfigured JdbcDaoImpl default DDL.
     */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http
                .authorizeHttpRequests((requests)-> requests
                        .requestMatchers("/","/home").permitAll() //These routes will not need authentication
                        .requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")).permitAll() //permits access to H2 console
                        .anyRequest().authenticated() //any other HTTP request, you will need to authenticate
                )
                .headers(headers -> headers.disable()) //we disable it to enable the H2 console page to load
                .csrf((csrf)->csrf
                        .ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**"))) //enables csrf security, its important if
                //the app has users that can log in. Customizer.withDefaults() is the default configuration
                //ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")) allows ignoring RequestMatchers for H2 console path
                .formLogin((form)-> form
                        //.loginPage("/login")
                        .defaultSuccessUrl("/hello")
                        .permitAll()
                        .failureHandler(authenticationFailureHandler())
                )
                .logout((logout)->logout
                        .logoutSuccessUrl("/")
                        .deleteCookies("JSESSIONID")
                        .invalidateHttpSession(true)
                        .permitAll())
//                .rememberMe((remember)->remember
//                        .rememberMeParameter("remember-me")
//                        .key("uniqueAndSecretKey")
//                        .tokenValiditySeconds(1000)
//                        .rememberMeCookieName("rememberloginnardone")
//                        .rememberMeParameter("remember-me"))
                .sessionManagement((session)->session //This part create always 1 session in the app
                        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                        .maximumSessions(1));


        return http.build();

    }
//    @Bean
//    public UserDetailsService userDetailsService(){
//        InMemoryUserDetailsManager inMemoryUserDetailsManager = new InMemoryUserDetailsManager();
//        inMemoryUserDetailsManager.createUser(User.withUsername("admin").password(passwordEncoder().encode("adminpassw")).roles("ADMIN").build());
//
//
//
////        UserDetails user =
////                User.withDefaultPasswordEncoder()
////                        .username("user")
////                        .password("password")
////                        .roles("USER")
////                        .build();
//        return inMemoryUserDetailsManager;
//    }
    //users with jdbc
    @Bean
    JdbcUserDetailsManager users(DataSource dataSource,PasswordEncoder encoder){
        UserDetails user = User.builder()
                .username("user")
                .password(encoder.encode("user"))
                .roles("USER")
                .build();
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        return jdbcUserDetailsManager;
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
    @Bean
    public EmbeddedDatabase datasource(){
        return new EmbeddedDatabaseBuilder()
                .setName("securitydb")
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }


}
