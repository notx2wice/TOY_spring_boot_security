# practice_spring_boot_security

# WebSecurityConfigurerAdapter의 configure을 오버라이딩 해서 설정을 변경할 수 있다. 
~~~ java
protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests((requests) -> {
            ((AuthorizedUrl)requests.anyRequest()).authenticated();
        });
        http.formLogin();
        /**이것을 수정해서 폼 개인 디폴트 로그인 페이지가 아닌 개인 설정
        로그인을 사용할수 있다.*/
        http.httpBasic();
    }
 ~~~
#####지금의 경우 anyRequest().qutenticated() 하기 때문에 모든 url에 .formLogin()이 적용되고 있는 상태이다.
application.properties 파일 값 추가
~~~
spring.security.user.name=user
spring.security.user.password=0000
~~~
이렇게 설정을 하면 매번 새로 생성되는 가계정 대신에 우리가 설정한 id, password가 생긴다.
원래라면 
~~~
Using generated security password: 97f36364-56da-445d-9ba5-bc4144022cac
~~~
이렇게 자동 생성됩니다.

#form login 인 
~~~ java

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
                .usernameParameter("userId")
                .passwordParameter("passWord")
                .loginPage("/loginPage") -> 이부분을 바꾸면 커스텀 로그인을 사용 할 수 있음.
                .loginProcessingUrl("/login_proc")
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
~~~
~~~ html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
  </head>
  <body>  
      <form class="form-signin" method="post" action="/loginProc">
        <p>
          <label for="username" class="sr-only">Username</label>
          <input type="text" id="username" name="userId" class="form-control" placeholder="Username" required autofocus>
        </p>
        <p>
          <label for="password" class="sr-only">Password</label>
          <input type="password" id="password" name="passWord" class="form-control" placeholder="Password" required>
        </p>
      </form>
  </body>
</html>
~~~
###위의 설정을 바꿈으로써 html이 이렇게 생성된다.

# 로그 아웃 설정
~~~ java
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
                    } // 세션 해제
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me") //쿠키 삭제
                ;
    }
}
~~~
http. logout을 추가 
기본적으로 로그아웃 성공시 어떤 url로 갈것인지
세션, 쿠키 정보 삭제를 수행 할 수 있다.

#Remember me
>세션이 만료되고 웹브라우저가 종료된 후에도 어플리케이션이 사용자를 기억하는 기능

>쿠키에 대한 http요청을 확인 후 토큰 기반 인증을 사용해 유효서을 검사 토큰이 검증되면 사용자는 로그인이 된다.

~~~ java
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
                .rememberMe()
                .rememberMeParameter("remember") 
                .tokenValiditySeconds(3600)// 기본 14일 유효기간
                .userDetailsService(userDetailsService) // 사용자 인증
                ;
    }
~~~