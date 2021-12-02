package com.example.mini_security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest()
                .authenticated();
        http
                .formLogin()
                //.loginPage("/loginPage")
                .usernameParameter("userId")
                .passwordParameter("passWord")
                .loginProcessingUrl("/loginProc")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        /**
                         * Authentication 안에는 인증 정보가 있다고 합니다.*/
                        System.out.println("로그인 성공입니다.");
                        System.out.println("authentication = " + authentication.getName());
                        httpServletResponse.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        System.out.println("예외 내용 = " + e);
                        httpServletResponse.sendRedirect("/login");
                    }
                })
                .permitAll();
                /**
                 * 위에서 설정한 해당 설정에 관해서는 모든 사용자가 접근 가능 해야한다 상식적으로 로그인페이지도 인증 받는건 말이 안됨
                 * */
    }
}
