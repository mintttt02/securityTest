package com.example.demo.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

@Entity
@Setter
@Getter
public class UserEntity {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) //PK 값을 자동 생성 시켜줄 수 있다.
    private int id;

    @Column(unique = true)
    private String username;
    private String password;

    private String role;
}

  
