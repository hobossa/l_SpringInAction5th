package com.example.tacocloud.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // super.configure(auth);

        // an in-memory user store
        // https://www.baeldung.com/spring-security-5-default-password-encoder
        // to fix java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        auth.inMemoryAuthentication()
                .withUser("buzz").password(encoder.encode("infinity")).authorities("ROLE_USER")
                .and().withUser("woody").password(encoder.encode("bullseye")).authorities("ROLE_USER")
                .and().withUser("tester").password(encoder.encode("pswd")).authorities("ROLE_ADMIN");
        // end (an in-memory user store)
    }

    // @SuppressWarnings("deprecation")
    // @Bean
    // public static NoOpPasswordEncoder passwordEncoder() {
    //     // https://www.harinathk.com/spring/no-passwordencoder-mapped-id-null/
    //     // https://www.baeldung.com/spring-security-5-default-password-encoder
    //     return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    // }
}
