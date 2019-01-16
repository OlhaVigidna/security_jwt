package com.example.security_jwt.model;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

public class LoginFilter extends AbstractAuthenticationProcessingFilter {

    public LoginFilter(AuthenticationManager authManager) {
        super(new AntPathRequestMatcher("/login", "POST"));
        setAuthenticationManager(authManager);
    }

//    @Override
//    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest,
//                                                HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {
//        ClientAuthModel model = new ObjectMapper().readValue(httpServletRequest.getInputStream(), ClientAuthModel.class);
//        System.out.println(model);
//         Authentication authentication = new UsernamePasswordAuthenticationToken(model.getUsername(), model.getPassword(), Collections.emptyList());
//        return authentication;
//    }
//
//    @Override
//    protected void successfulAuthentication(HttpServletRequest request,
//                                            HttpServletResponse response,
//                                            FilterChain chain,
//                                            Authentication authResult) throws IOException, ServletException {
//
//    }

    //    During the authentication attempt,
// which is dealt by the attemptAuthentication method,
// we retrieve the username and password from the request.
// After they are retrieved, we use the AuthenticationManager to verify that these details match with an existing user.
// If it does, we enter the successfulAuthentication method.
// In this method we fetch the name from the authenticated user,
// and pass it on to TokenAuthenticationService, which will then add a JWT to the response.

    private AccountCredentials creds;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {
         creds = new ObjectMapper()
                .readValue(httpServletRequest.getInputStream(), AccountCredentials.class);
        return getAuthenticationManager().authenticate(
                new UsernamePasswordAuthenticationToken(
                        creds.getUsername(),
                        creds.getPassword(),
                        Collections.emptyList()
                )
        );
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest req,
            HttpServletResponse res, FilterChain chain,
            Authentication auth) throws IOException, ServletException {
        String name = auth.getName();
        String jwtoken = Jwts.builder()
                .setSubject(name)
                .sighWith(SignatureAlgorithm.HS512, "yes".getBytes())
//                .setExpiration(new Date(System.currentTimeMillis()+200000))
                .compact;
        res.addHeader("Authorization", "Bearer" + jwtoken);
    }
}


