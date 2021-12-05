package com.example.mini_security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    final UserDetailsService userDetailsService;
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
                .permitAll()
                ;
                /**
                 * 위에서 설정한 해당 설정에 관해서는 모든 사용자가 접근 가능 해야한다 상식적으로 로그인페이지도 인증 받는건 말이 안됨
                 * */
        http
                .logout()
                .logoutUrl("/logout") //기본적으로 post방식
                .logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
                        HttpSession session = httpServletRequest.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me")
                ;
        http
                .rememberMe()
                .rememberMeParameter("remember")
                .tokenValiditySeconds(3600)// 기본 14일
                .userDetailsService(userDetailsService)
                ;
        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                .sessionFixation().changeSessionId()
                .maximumSessions(1) //세션 의 최대 수
                .maxSessionsPreventsLogin(true)
                ;
        /**
         *
         * .sessionCreationPolicy()   default SessionCreationPolicy.If_Required :: 시큐리티가 필요시 생성
         *                                    SessionCreationPolicy.Always :: 시큐리티가 세션을 항상 생성
         *                                    SessionCreationPolicy.Never :: 시큐리티가 생성하지 않지만 있으면 사용
         *                                    SessionCreationPolicy.Stateless :: 시큐리티가 생성하지 않고 있어서 사용 x ex)jwt
         *
         * maxSessionsPreventsLogin() default false :: 최대 세션 수를 초과 하였을 떄 오래된 세션 종료
         *                                    true :: 추가 세션 생성을 막는다.
         *
         * .sessionFixation()         default changeSessionId() :: 약용자가 세션id를 받은후 그 세션 아이디를
         *                                                         피해자의 브라우저에 등록한후 피해자가 로그인을(인증) 을 하게 되면
         *                                                         악용자 피해자 모두 접속된 상태가 된다.
         *                                                         이를 막기위해 인증을 성공하게 되면 세션id를 새로 생성하게 된다.
         */

    }
}
