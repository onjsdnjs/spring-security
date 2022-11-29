package io.security.springsecurity.controller.admin;

import io.security.springsecurity.domain.entity.RoleHierarchy;
import io.security.springsecurity.repository.RoleHierarchyRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;

@Controller
public class RoleHierarchyController {

	@Autowired
	private RoleHierarchyRepository roleHierarchyRepository;

	@GetMapping(value="/admin/roleHierarchy")
	public String getRoleHierarchy(Model model) throws Exception {

		List<RoleHierarchy> roleHierarchy = roleHierarchyRepository.findAll();
		model.addAttribute("roleHierarchy", roleHierarchy);

		return "admin/roleHierarchy/list";
	}
}
