package com.example.security_jwt.config;



import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class Security extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("asd").password("{noop}asd").roles("ADMIN");
        auth.inMemoryAuthentication().withUser("qwe").password("{noop}qwe").roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf()
                .disable()
                .authorizeRequests()
                .anyRequest().authenticated()
                .antMatchers("/").permitAll()
                .antMatchers(HttpMethod.POST, "/login").permitAll()
                .and()
                .addFilterBefore(new LoginFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new RequestProcessingJWTFilter(),
                        UsernamePasswordAuthenticationFilter.class);


//                // We filter the api/login requests
//                .addFilterBefore(new LoginFilter("/login", authenticationManager()),
//                        UsernamePasswordAuthenticationFilter.class)
//                // And filter other requests to check the presence of JWT in header
    }



}
