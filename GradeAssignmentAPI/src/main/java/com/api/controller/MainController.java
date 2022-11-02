package com.api.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.api.dao.EmployeeRepository;
import com.api.entities.Employee;
import com.api.service.EmployeeService;

@RestController
@RequestMapping("/api")
public class MainController {
	
	@Autowired
	EmployeeService employeeService;
	
	
	
	@GetMapping("/employees")
	public List<Employee> getAll(){
		return employeeService.getAll();
		
	}
	
	@GetMapping("/employees/{id}")
	public Employee get(@PathVariable("id") int id,HttpStatus httpStatus) {
		
		
		Employee emp = employeeService.findById(id);
	
		
		return emp;
	}
	
	@PostMapping("/post")
	public Employee create(@RequestBody Employee employee) {
		return employeeService.save(employee);
	}
	
	//update by using id
	@PutMapping("/update/{id}")
	public Employee update(@PathVariable("id") int id, @RequestBody Employee emp) {
		emp.setId(id);
		return employeeService.update(emp);
	}
	
	//update by using object where id is given
	@PutMapping("/update")
	public Employee updateObject(@RequestBody Employee emp) {
		
		return employeeService.save(emp);
	}
	
	@DeleteMapping("/delete/{id}")
	public String delete(@PathVariable("id") int id) {
		return employeeService.deleteById(id);
	}
	
	@GetMapping("/search/{name}")
	public List<Employee> search(@PathVariable("name") String name){
		return employeeService.findByName(name);
	}
	
	@GetMapping("/sort")
	public List<Employee> sort(@RequestParam("order") String order){
	
		return employeeService.sort(order);
	}
	
	

}
