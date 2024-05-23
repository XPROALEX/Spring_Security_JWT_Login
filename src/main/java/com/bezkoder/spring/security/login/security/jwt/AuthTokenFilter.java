package com.bezkoder.spring.security.login.security.jwt;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.bezkoder.spring.security.login.security.service.UserDetailsServiceImpl;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

//estentendo OncePerRequestFilter, il che significa che il filtro viene eseguito una volta per ogni richiesta HTTP
public class AuthTokenFilter extends OncePerRequestFilter {

	@Autowired
	private JwtUtils jwtUtils;

	@Autowired
	private UserDetailsServiceImpl userDetailsServiceImpl;

	private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			// Chiama il metodo parseJwt per estrarre il token JWT dalla richiesta.
			String jwt = parseJwt(request);
			
			// Se il token esiste e è valido, procede con l'estrazione del nome utente.
			if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
				
				String username = jwtUtils.getUserNameFromJwtToken(jwt);

				UserDetails userDetails = userDetailsServiceImpl.loadUserByUsername(username);
				
				//utilizzata per incapsulare le informazioni durante il processo di autenticazione
				//principal) è l'oggetto che rappresenta i dettagli dell utente (userDetail)
				//credentials) solitamente va inserita la passowrd ma in questo caso inseriamo il null
				//perche si sta autenticando l'utente tramite il token jwt
				//authorities) ruoli o autorizzazioni dell utente 
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());

				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		} catch (Exception e) {
			logger.error("Cannot set user authentication: {}", e);
		}

		filterChain.doFilter(request, response);

	}

	// strae il token JWT dai cookie della richiesta tramite il metodo
	// getJwtFromCookies della classe JwtUtils.
	private String parseJwt(HttpServletRequest request) {
		String jwt = jwtUtils.getJwtFromCookies(request);
		return jwt;
	}

}

/*
 * Il filtro AuthTokenFilter fa quanto segue per ogni richiesta:
 * 
 * Estrae il token JWT dalla richiesta. 
 * Valida il token. 
 * Se il token è valido,estrae il nome utente dal token. 
 * Carica i dettagli dell'utente dal database.
 * Crea un oggetto di autenticazione e lo imposta nel contesto di sicurezza di Spring.  
 * 
 * Questo permette all'applicazione di autenticare gli utenti basandosi su token JWT nelle
 * richieste, mantenendo un contesto di sicurezza per ogni richiesta autenticata.
 */
