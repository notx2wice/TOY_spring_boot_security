# practice_spring_boot_security

#####WebSecurityConfigurerAdapter의 configure을 오버라이딩 해서 설정을 변경할 수 있다. 
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

~~~
spring.security.user.name=user
spring.security.user.password=0000
~~~
이렇게 설정을 하면 매번 새로 생성되는 가계정 대신에 우리가 설정한 id, password가 생긴다.
####원래라면 
~~~
Using generated security password: 97f36364-56da-445d-9ba5-bc4144022cac
~~~
이렇게 자동 생성됩니다.