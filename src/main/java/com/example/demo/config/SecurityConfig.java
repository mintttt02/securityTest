package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
            .authorizeHttpRequests((auth) -> auth
                .requestMatchers("/", "/login").permitAll() //모두접근가능
                .requestMatchers("/admin").hasRole("ADMIN")
                .requestMatchers("/myPage/**").hasAnyRole("ADMIN", "USER")
                .requestMatchers("/denyAll").denyAll() //모두접근불가
                .anyRequest().authenticated()
            )
            .formLogin((auth) -> auth
                .loginPage("/login")
                .loginProcessingUrl("/loginProc")
                .permitAll()
            )
            .csrf((auth) -> auth.disable());

        return http.build();
    }

    //password 단방향 암호화
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

}
