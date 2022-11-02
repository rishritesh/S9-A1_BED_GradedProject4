package com.api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.api.service.UserServiceImpl;

@Configuration
@EnableWebSecurity
public class MyConfig extends WebSecurityConfigurerAdapter{
	
	@Bean
	public UserDetailsService getUserDetails() {
		return new UserServiceImpl();
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new  BCryptPasswordEncoder();
	}
	
	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider daoAuthenticationProvider= new DaoAuthenticationProvider();
		daoAuthenticationProvider.setUserDetailsService(this.getUserDetails());
		daoAuthenticationProvider.setPasswordEncoder(this.passwordEncoder());
		return daoAuthenticationProvider;
	}

	//configuration 
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// TODO Auto-generated method stub
		auth.authenticationProvider(authenticationProvider());
			
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf()
		.disable()
		.authorizeRequests()
		.antMatchers("/api/**").hasAnyAuthority("ADMIN")
		.antMatchers("/user/**").permitAll()
		.anyRequest()
		.authenticated()
		.and()
		.httpBasic();
		
		
//		http
//		  .authorizeRequests()
//		  .antMatchers("/user/**").permitAll()
//		  .antMatchers("/api/**").hasAnyAuthority("ADMIN")
//		  .anyRequest().authenticated() .and().formLogin()
//		  .and() 
//		  .csrf() 
//		  .disable();
		
	}
	
	
//	 http
//	  .authorizeRequests()
//	  .antMatchers("/admin/**").hasRole("ADMIN")
//	  .antMatchers("/user/**").hasRole("USER")
//	  .antMatchers("/**").permitAll()  .and()
//	  .formLogin().loginPage("/signin").defaultSuccessUrl("/default",true)
//	  .and() 
//	  .csrf() 
//	  .disable();
//
//	http.authorizeRequests()
//	.antMatchers("/","/add","/handler", "/403").hasAnyAuthority("USER","ADMIN")
//	.antMatchers("/update/**", "/delete/**").hasAuthority("ADMIN")
//	.anyRequest().authenticated()
//	.and()
//	.formLogin().loginProcessingUrl("/login").successForwardUrl("/").permitAll()
//	.and()
//	.logout().logoutSuccessUrl("/login").permitAll()
//	.and()
//	.exceptionHandling().accessDeniedPage("/403")
//	.and()
//	.cors().and().csrf().disable();

}
