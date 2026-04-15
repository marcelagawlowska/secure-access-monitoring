# secure-access-monitoring

Secure Access Monitor is a Spring Boot project about safe sign-in, account checks, and security logs.

## Overview

This project is a small demo of secure access logic.

The user does not type threat data by hand. The app tries to detect it on its own. It can notice things like:
- a new browser
- a new source address
- repeated failed password checks
- a more sensitive account action

The goal was not to build a full production system. I wanted to make a clear project that shows a few real security ideas in one app.

## Features

- user registration
- password hashing with BCrypt
- sign-in with Spring Security
- failed-attempt counter and account lockout
- known device tracking with a browser cookie
- known source tracking
- protected action check based on session context
- per-user security logs
- simple web UI for testing the full flow

## Tech stack

- Java 17
- Spring Boot 3
- Spring Web
- Spring Data JPA
- Spring Security
- H2 Database
- HTML, CSS, JavaScript

## How it works

1. A user creates an account and signs in.
2. After sign-in, the app remembers the current browser and source.
3. When the password is checked again, the app verifies it, counts failed attempts, and can lock the account.
4. When a protected action is requested, the backend checks the action type and the current session context.
5. The app returns a result with a risk level.
6. Every important step is saved in the security log.

## Run locally

Requirements:

- Java 17 or newer
- Git

Steps:

1. Clone the repository:

   ```bash
   git clone https://github.com/marcelagawlowska/secure-access-monitoring.git
   cd secure-access-monitoring
   ```

2. Start the application:

   ```bash
   ./mvnw spring-boot:run
   ```

   On Windows:

   ```bash
   mvnw.cmd spring-boot:run
   ```

3. Open [http://localhost:8081/](http://localhost:8081/).

The application can also be started from IntelliJ IDEA by running `banksecurity.SecureAccessMonitoringApplication`.

## Main page

From the main page you can:

- create a test account
- go to sign in
- check the password again for the current session
- run a protected action check
- load the security log
- run a few ready test cases
