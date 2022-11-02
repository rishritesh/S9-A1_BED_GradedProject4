package com.api.service;

import java.util.List;
import java.util.Optional;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;

import com.api.dao.EmployeeRepository;
import com.api.entities.Employee;

@Service
public class EmployeeService {
	
	
	@Autowired
	EmployeeRepository employeeRepository;
	
	//get All data 
	public List<Employee> getAll(){
		return employeeRepository.findAll();
	}
	

	
	@Transactional
	//save the data
	public Employee save(Employee employee) {
		return employeeRepository.save(employee);
	}
	
	@Transactional
	//get specific data
	public Employee findById(int id) {
		
		Optional<Employee> employee = employeeRepository.findById(id);
		Employee employee2 = employee.get();
		return employee2;
	}
	
	@Transactional
	//delete the data
	public String deleteById(int id) {
		Employee employee = employeeRepository.findById(id).get();
		employeeRepository.delete(employee);
		return "Deleted Employee id "+id;
	}
	
	@Transactional
	//update the data
	public Employee update(Employee emp) {
		return employeeRepository.save(emp);
	}
	
	
	public List<Employee> findByName(String name) {
		return employeeRepository.findByFirstname(name);
	}
	
	//for sorting asc or desc order
	@Transactional
	public List<Employee> sort(String order){
		
		//order is not string format it come with quotes thats why we check contains.
		if(order.equals("\"asc\"")) {
			System.out.println(order);
			return employeeRepository.findAll(Sort.by(Direction.ASC, "firstname"));
		}
		System.out.println("hi"+order);
		return employeeRepository.findAll(Sort.by(Direction.DESC, "firstname"));
	}


}
