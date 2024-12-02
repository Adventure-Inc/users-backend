# **User Management Service**

This project is a **User Management Service** implemented in **Golang**, designed to handle user registration, authentication, and profile management. The service provides RESTful APIs for user-related functionalities and serves as the authentication and user management component for Adventures app.

---

## **Features**

- User registration with secure password storage using bcrypt.
- User login with JWT-based authentication.
- JWT token validation for protected routes.
- Modular architecture for scalability and maintainability.
- Lightweight and fast backend using **Golang**.

---


# **Directory Structure Breakdown**

## **Top-Level Files**
- **`main.go`**: 
  - The entry point of the application.
  - Initializes the database connection, sets up the routing, and starts the HTTP server.

- **`go.mod`**:
  - Declares the module name and lists the dependencies required by the application.

- **`go.sum`**:
  - Contains the checksums of the dependencies, ensuring reproducibility and consistency.

---


## **Folders and Their Contents**

### **models/**
This folder defines the database schema and models used throughout the application.

- **`models/user.go`**:
  - Defines the `User` struct, which represents the user table in the database.
  - Example:
    ```go
    type User struct {
        ID             uint   `gorm:"primaryKey"`
        Name           string
        Email          string `gorm:"uniqueIndex"`
        HashedPassword string
    }
    ```

---

### **controllers/**
This folder contains the HTTP handlers (controllers) that process requests and send responses. It connects the API endpoints with the services.

- **`controllers/user_controller.go`**:
  - Handles user-related API requests, such as registration, login, and profile retrieval.
  - Example:
    - `RegisterUser`: Handles user registration.
    - `LoginUser`: Validates credentials and generates JWTs.

 Keeps raw database operations abstracted from the rest of the code.

---

### **middleware/**
This folder contains middleware functions used across the application for tasks such as authentication and logging.

- **`middlewares/auth_middleware.go`**:
  - Implements middleware to:
    - Validate incoming JWT tokens.
    - Extract user information from the token.
    - Protect routes from unauthorized access.

---

### **routes/**
This folder defines the routing for the application, mapping API endpoints to their respective controllers.

- **`routes/user_routes.go`**:
  - Registers the user management endpoints (e.g., `/register`, `/login`, `/profile`) and connects them to the `user_controller` handlers.

---

### **Summary of Responsibilities**

| **Folder/File**            | **Responsibility**                                                                 |
|----------------------------|-----------------------------------------------------------------------------------|
| **`main.go`**              | Application entry point, server initialization.                                   |
| **`models/`**              | Database schema and models (e.g., `User`).                                        |
| **`controllers/`**         | Handles API requests and responses.                                              |                    |
| **`middleware/`**         | Reusable middleware (e.g., JWT validation).                                      |
| **`routes/`**              | Maps API endpoints to their respective controllers.                              |
| **`go.mod` and `go.sum`**  | Dependency management and reproducibility.  