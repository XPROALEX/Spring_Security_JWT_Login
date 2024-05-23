# Spring Security JWT Login

Questo progetto dimostra l'implementazione di un sistema di autenticazione basato su JSON Web Token (JWT) utilizzando Spring Security in un'applicazione Spring Boot.

## Tecnologie Utilizzate

- Java
- Spring Boot
- Spring Security
- MySQL
- Altre dipendenze utilizzate nel progetto

## Descrizione

Spring Security JWT Login è un'applicazione dimostrativa che illustra come implementare un sistema di autenticazione sicuro utilizzando JSON Web Token (JWT) come meccanismo di autenticazione.
Questo tipo di autenticazione è ampiamente utilizzato per applicazioni web moderne che necessitano di una gestione sicura delle sessioni utente.

## Funzionalità Principali

- **Registrazione di nuovi utenti**: Gli utenti possono registrarsi fornendo le proprie credenziali.
- **Login degli utenti esistenti**: Gli utenti possono effettuare l'accesso utilizzando le credenziali registrate.
- **Generazione e gestione dei token JWT per autenticazione**: I token JWT vengono utilizzati per autenticare gli utenti e consentire l'accesso alle risorse protette.
- **Accesso a risorse protette tramite autorizzazione basata su ruoli**: Gli utenti con ruoli specifici possono accedere a risorse protette.

## Requisiti di Sistema

- Java JDK 8 o versione successiva
- Apache Maven
- MySQL Server

## Configurazione

Per configurare l'applicazione, è necessario modificare i file di configurazione Spring Boot per adattarli alla propria configurazione di database e altri parametri specifici dell'applicazione.

## Installazione
Per eseguire l'applicazione, seguire i seguenti passaggi:

1. Clonare il repository: `git clone https://github.com/XPROALEX/Spring_Security_JWT_Login.git`
2. Navigare nella directory del progetto: `cd Spring_Security_JWT_Login`
3. Compilare il progetto utilizzando Maven: `mvn clean install`
4. Avviare l'applicazione: `java -jar target/Spring_Security_JWT_Login.jar`

## Utilizzo

Per utilizzare l'applicazione, è richiesto l'utilizzo di un client API REST come Postman. Seguire le istruzioni fornite di seguito:

1. Creare un database nel tuo server MySQL.
2. Modificare i dati di accesso nel file `application.properties`.
3. Eseguire l'applicazione per consentire ad Hibernate la creazione delle tabelle nel database.
4. Inserire i ruoli necessari nel database con le query SQL seguenti:
    ```sql
    INSERT INTO roles(name) VALUES('ROLE_USER');
    INSERT INTO roles(name) VALUES('ROLE_MODERATOR');
    INSERT INTO roles(name) VALUES('ROLE_ADMIN');
    ```
5. Registrare un nuovo utente inviando una richiesta POST all'endpoint: `http://localhost:8080/api/auth/signup`.
    ```json
    {
        "username": "Mod",
        "email": "mod@mail.com",
        "password": "password",
        "role": ["mod","user"]
    }
    ```
6. Effettuare il login inviando una richiesta POST all'endpoint: `http://localhost:8080/api/auth/signin`.
    ```json
    {
        "username":"Mod",
        "password":"password"
    }
    ```
7. Accedere alle risorse protette inviando richieste GET con filtro, ad esempio, la dashboard del moderatore: `http://localhost:8080/api/test/mod`.
8. Effettuare il logout e pulire i cookie inviando una richiesta POST all'endpoint: `http://localhost:8080/api/auth/signout`.

## Contribuire

Sono benvenuti i contributi sotto forma di segnalazioni di bug, richieste di nuove funzionalità o miglioramenti del codice. Per contribuire, aprire una nuova issue o inviare una pull request.

## Contatti

- [Profilo GitHub di XPROALEX](https://github.com/XPROALEX)
