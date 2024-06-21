package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyUtils;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf((auth) -> auth.disable()); //개발환경에서만 사용, 배포환경에서는 토큰검증 필요, api환경에서는 필요없다고 함

        http.authorizeHttpRequests((auth) -> 
            auth
                .requestMatchers("/", "/login", "/loginProc", "/join", "/joinProc").permitAll() //모두접근가능
                .requestMatchers("/admin").hasRole("ADMIN")
                .requestMatchers("/myPage/**").hasAnyRole("ADMIN", "USER")
                .requestMatchers("/denyAll").denyAll() //모두접근불가
                .anyRequest().authenticated()
            );

        //계층 권한 : Role Hierarchy
       /*  http.authorizeHttpRequests((auth) -> 
            auth
                .requestMatchers("/login").permitAll()
                .requestMatchers("/").hasAnyRole("A", "B", "C")
                .requestMatchers("/manager").hasAnyRole("B", "C")
                .requestMatchers("/admin").hasAnyRole("C")
                .anyRequest().authenticated()
            ); */

        http.formLogin((auth) -> 
            auth
                .loginPage("/login")
                .loginProcessingUrl("/loginProc")
                .permitAll()
            );

        // formLogin 방식 대신 사용
        // Http Basic 인증 방식은 아이디와 비밀번호를 Base64 방식으로 인코딩한 뒤 HTTP 인증 헤더에 부착하여 서버측으로 요청을 보내는 방식
        // 브라우저에서 자동으로 로그인 팝업창이 뜸
        //http.httpBasic(Customizer.withDefaults());

        http.sessionManagement((auth) -> 
            auth
                .maximumSessions(1) //하나의 id에 대해 다중로그인을 허용하는 개수
                .maxSessionsPreventsLogin(true) //다중로그인 개수를 초과한 경우 true : 로그인 차단, false : 기존 session 차단 후 새로운session 생성 
                .expiredUrl("/login?expired")
            );
        
        //세션 고정 공격 방지
        http.sessionManagement((auth) -> 
            auth
                .sessionFixation().changeSessionId() //로그인 시 동일한 세션에 대한 id 변경
            );

        //로그아웃
        http.logout((auth) -> 
            auth
                .logoutUrl("/logout")
                .logoutSuccessUrl("/")
            );

        return http.build();
    }

    //password 단방향 암호화
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    //계층 권한 : Role Hierarchy
    @SuppressWarnings("deprecation")
    @Bean
    public RoleHierarchy roleHierarchy() {

        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();

        hierarchy.setHierarchy("ROLE_C > ROLE_B\n" + "ROLE_B > ROLE_A");

        return hierarchy;
    }

    //회원가입 없는 InMemory 방식으로 유저를 저장
    @Bean
    public UserDetailsService userDetailsService() {

        UserDetails user1 = User.builder()
                .username("admin1")
                .password(bCryptPasswordEncoder().encode("1234"))
                .roles("ADMIN")
                .build();

        UserDetails user2 = User.builder()
                .username("user2")
                .password(bCryptPasswordEncoder().encode("1234"))
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user1, user2);
    }

}
