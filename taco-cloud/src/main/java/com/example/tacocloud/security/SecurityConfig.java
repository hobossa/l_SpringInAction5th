package com.example.tacocloud.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // JDBC Authentication
    // @Autowired
    // DataSource dataSource;
    // end (JDBC Authentication)

    // Customizing user authentication
    @Autowired
    private UserDetailsService userDetailsService;
    // end (Customizing user authentication)

    /*
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // super.configure(http);
        // requests for /design and /orders are only available to authenticated
        // users; all other requests should be permitted for all users.
        // http.authorizeRequests()
        //         .antMatchers("/design", "/orders").hasRole("ROLE_USER")
        //         .antMatchers("/", "/**").permitAll();


        // Using Spring expressions to define authorization rules (more flexible)
        // allow users with ROLE_USER authority to create new tacos on Tuesdays
        // http.authorizeRequests()
        //         .antMatchers("/design", "/orders").access(
        //                 "hasRole('ROLE_USER') && " +
        //                         "T(java.util.Calendar).getInstance().get("+
        //                         "T(java.util.Calendar).DAY_OF_WEEK) == " +
        //                         "T(java.util.Calendar).TUESDAY")
        //         .antMatchers("/", "/**").permitAll();


        // The and() method signifies that you’re
        // finished with the authorization configuration and are ready to apply some additional
        // HTTP configuration. You’ll use and() several times as you begin new sections
        // of configuration.
        http.authorizeRequests()
                .antMatchers("/design", "/orders").access("hasRole('ROLE_USER')")
                .antMatchers("/", "/**").permitAll()
                .and()
                .formLogin().loginPage("/login")
                // .loginProcessingUrl("/authenticate")
                // .usernameParameter("user")
                // .passwordParameter("pwd")
                .and()
                .logout()
                .logoutSuccessUrl("/")
                // Make H2-Console non-secured; for debug purposes
                .and()
                .csrf()
                .ignoringAntMatchers("/h2-console/**")
                // Allow pages to be loaded in frames from the same origin; needed for H2-Console
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()
                ;



    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // super.configure(auth);

        ///////////////////////////////////
        // // an in-memory user store
        // // https://www.baeldung.com/spring-security-5-default-password-encoder
        // // to fix java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"
        // PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        // auth.inMemoryAuthentication()
        //         .withUser("buzz").password(encoder.encode("infinity")).authorities("ROLE_USER")
        //         .and().withUser("woody").password(encoder.encode("bullseye")).authorities("ROLE_USER")
        //         .and().withUser("tester").password(encoder.encode("pswd")).authorities("ROLE_ADMIN");
        // // end (an in-memory user store)


        ///////////////////////////////////
        // // JDBC Authentication
        // // the database is supposed to meet the following queries. or you need to customize user detail queries.
        // // public static final String DEF_USERS_BY_USERNAME_QUERY =
        // //         "select username,password,enabled " +
        // //                 "from users " +
        // //                 "where username = ?";
        // // public static final String DEF_AUTHORITIES_BY_USERNAME_QUERY =
        // //         "select username,authority " +
        // //                 "from authorities " +
        // //                 "where username = ?";
        // // public static final String DEF_GROUP_AUTHORITIES_BY_USERNAME_QUERY =
        // //         "select g.id, g.group_name, ga.authority " +
        // //                 "from groups g, group_members gm, group_authorities ga " +
        // //                 "where gm.username = ? " +
        // //                 "and g.id = ga.group_id " +
        // //                 "and g.id = gm.group_id";
        //
        // // auth.jdbcAuthentication().dataSource(dataSource); // using default queries.
        //
        // // customizing user detail queries
        // auth.jdbcAuthentication().dataSource(dataSource)
        //         .usersByUsernameQuery("SELECT username, password, enabled FROM Users WHERE username=?")
        //         .authoritiesByUsernameQuery("SELECT username,authority from UserAuthorities WHERE username=?")
        //         .passwordEncoder(new BCryptPasswordEncoder());
        // // override the authorities by calling groupAuthoritiesByUsername()
        //
        // // end (JDBC Authentication)


        ///////////////////////////////////
        // // LDAP-backed user store
        // // auth.ldapAuthentication()
        // //         .userSearchFilter("(uid={0})")
        // //         .groupSearchFilter("member={0})");
        //
        // // The userSearchFilter() and groupSearchFilter() methods are used to provide filters
        // // for the base LDAP queries, which are used to search for users and groups. By
        // // default, the base queries for both users and groups are empty, indicating that the
        // // search will be done from the root of the LDAP hierarchy. But you can change that by
        // // specifying a query base:
        // // the following example specifies that users be searched for where the organizational
        // // unit is people. Groups should be searched for where the organizational
        // // unit is groups.
        // auth.ldapAuthentication()
        //         .userSearchBase("ou=people")
        //         .userSearchFilter("(uid={0})")
        //         .groupSearchBase("ou=groups")
        //         .groupSearchFilter("member={0}")
        //         .passwordCompare()
        //         .passwordEncoder(new BCryptPasswordEncoder())
        //         .passwordAttribute("passcode")
        //         .and()
        //         .contextSource()
        //         .root("dc=tacocloud,dc=com")
        //         .ldif("classpath:users.ldif");
        // // end (LDAP-backed user store)

        /////////////////////////////
        // Customizing user authentication
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(encoder());
        // end (Customizing user authentication)

    }

    */
    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    // @SuppressWarnings("deprecation")
    // @Bean
    // public static NoOpPasswordEncoder passwordEncoder() {
    //     // https://www.harinathk.com/spring/no-passwordencoder-mapped-id-null/
    //     // https://www.baeldung.com/spring-security-5-default-password-encoder
    //     return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    // }
}
