package com.alex.spring.security.login.controller;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.alex.spring.security.login.model.ERole;
import com.alex.spring.security.login.model.Role;
import com.alex.spring.security.login.model.User;
import com.alex.spring.security.login.payload.request.LoginRequest;
import com.alex.spring.security.login.payload.request.SignupRequest;
import com.alex.spring.security.login.payload.response.MessageResponse;
import com.alex.spring.security.login.payload.response.UserInfoResponse;
import com.alex.spring.security.login.repository.RoleRepository;
import com.alex.spring.security.login.repository.UserRepository;
import com.alex.spring.security.login.security.jwt.JwtUtils;
import com.alex.spring.security.login.security.service.UserDetailsImpl;

import jakarta.validation.Valid;

// Permette richieste cross-origin da qualsiasi origine, 
// con un tempo massimo di cache delle preflight requests di 3600 secondi.
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtUtils jwtUtils;
	/*
	 * Autenticazione dell'utente:
	 * 
	 * Utilizza authenticationManager per autenticare l'utente con username e
	 * password presi da loginRequest.
	 * Se le credenziali sono corrette, authenticationManager.authenticate 
	 * restituisce un'istanza di Authentication.
	 * 
	 * imposta il contesto di sicurezza:
	 * 
	 * Il contesto di sicurezza di Spring (SecurityContextHolder) viene aggiornato
	 * con le informazioni di autenticazione. 
	 * 
	 * Estrae i dettagli dell'utente:
	 * UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();: 
	 * Ottiene i dettagli dell'utente autenticato.
	 * 
	 * Generazione del JWT:
	 * 
	 * Genera un cookie contenente il JWT usando
	 * jwtUtils.generateJwtCookie. 
	 * 
	 * Costruzione della risposta:
	 * 
	 * Ottiene i ruoli dell'utente e li trasforma in una lista di stringhe.
	 * Restituisce una risposta ResponseEntity contenente il cookie JWT e le
	 * informazioni dell'utente (id, username, email, ruoli).
	 */

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);

		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

		ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

		List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
				.collect(Collectors.toList());
		
		String jwt = jwtCookie.getValue();
	    System.out.println("Token generato durante il login: " + jwt); // Aggiunto per visualizzare il token generato

		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString()).body(
				new UserInfoResponse(userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles));
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
		if (userRepository.existsByUsername(signupRequest.getUsername())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
		}

		if (userRepository.existsByEmail(signupRequest.getEmail())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
		}

		// Create new user's account

		User user = new User();
		user.setUsername(signupRequest.getUsername());
		user.setEmail(signupRequest.getEmail());
		user.setPassword(encoder.encode(signupRequest.getPassword()));

		Set<String> strRoles = signupRequest.getRole();
		Set<Role> roles = new HashSet();

		if (strRoles == null || strRoles.isEmpty()) {
			Role userRole = roleRepository.findByName(ERole.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				switch (role) {
				case "admin":
					Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(adminRole);

					break;
				case "mod":
					Role moderatorRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(moderatorRole);

					break;
				default:
					Role userRole = roleRepository.findByName(ERole.ROLE_USER)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(userRole);
				}
			});
		}

		user.setRoles(roles);
		userRepository.save(user);

		return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	}

	// Genera un cookie JWT pulito (con valore null) per cancellare il token JWT dal
	// browser dell'utente.
	@PostMapping("/signout")
	public ResponseEntity<?> logoutUser() {
		ResponseCookie cookie = jwtUtils.getCleanJwtCookie();

		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
				.body(new MessageResponse("You've been signed out!"));
	}

}
