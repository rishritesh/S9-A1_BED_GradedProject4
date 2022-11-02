package com.api.dao;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.api.entities.User;

@Repository
public interface UserRepository extends JpaRepository<User, Integer>{
	
	
	public User findByUsername(String username);


}
