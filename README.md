# Authentication API

## Folder Structure

```
.
├── cmd
│   └── api
│   │   └── main.go
├── internal
│   ├── api
│   │   ├── handlers
│   │   │   └── *_handler.go
│   │   └── routes
│   │       └── routes.go
│   ├── config
│   │   └── config.go
│   ├── db
│   │   ├── connection.go
│   │   └── models.go
│   └── services
│       └── *_service.go
```

- **cmd**: This folder contains the entry point for the application, including the main application logic.
- **internal**: This folder contains the internal implementation details of the application, including API handlers, routes, and database models.

- **internal/api**: This folder contains the API implementation details, including request handlers and routing.
- **internal/config**: This folder contains the configuration-related code, including loading environment variables and application settings.
- **internal/db**: This folder contains the database connection and model definitions.
- **internal/services**: This folder contains the business logic and service layer code.
