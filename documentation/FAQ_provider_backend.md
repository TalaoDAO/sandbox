# FAQ Wallet Provider Backend

## What is the Wallet Provider Backend?

- The Wallet Provider Backend is a system that enables administrators to configure wallet behaviors, manage verifiable credentials (VCs), and integrate external services for user authentication and credential issuance.
- It provides secure, scalable management of wallets for personal and enterprise use, supporting verifiable credentials in various formats.

## How do I set up the Wallet Provider Backend?

1. **Clone the Repository**: Download the project from the repository (e.g., GitHub).
2. **Install Dependencies**: Use `pip` to install necessary libraries.
3. **Configure Environment Variables**: Set up API keys, MongoDB credentials, Redis URL, and other provider settings in the environment configuration file.
4. **Run the Server**: Start the Flask server, ensuring connections to MongoDB and Redis are established.

## What APIs are available in the Wallet Provider Backend?

- **User Authentication API**: Provides secure OAuth2 and client-secret-based methods for managing user sessions.
- **Verifiable Credentials API**: Issue, store, and revoke VCs.
- **Configuration Management API**: Manage wallet types, issuer selections, and user roles.
- **Integration with Identity Providers**: Connect with external issuers and verifiers.

## How is user authentication handled?

- **OAuth2 and SIOPV2** are supported for secure authentication.
- Token-based authentication mechanisms are used to validate users' access and identity in the wallet app.

## How can I manage verifiable credentials?

- The backend supports multiple VC formats such as **JWT VC** and **LDP VC**.
- Credentials are securely stored in **MongoDB**, with encryption to ensure data privacy.
- VCs can be issued, revoked, and presented using the backend's APIs.

## What databases are supported?

- **MongoDB**: Used for long-term storage of users, credentials, and configurations.
- **Redis**: Provides session management and caching services.

## How do I configure wallet features via the backend?

- Configuration settings such as primary colors, wallet types, issuer preferences, and security options can be managed via the API or the admin dashboard.
- Updates to these configurations are applied dynamically, reflecting changes in the wallet app without requiring reinstallation.

## How do I deploy the Wallet Provider Backend?

1. **Prepare the Environment**: Set up the necessary environments (development, staging, production).
2. **Build the Backend**: Ensure all configurations, API keys, and credentials are correctly set in the environment files.
3. **Deploy**: Use deployment platforms such as **AWS**, **Google Cloud**, or **Heroku** for deployment.
4. **Monitor**: Use logging and monitoring tools to track backend performance and detect any issues.

## How are security and encryption managed?

- **OAuth2 and HTTPS** ensure secure communication between users and the backend.
- All sensitive data, including VCs and user information, is encrypted and stored securely in MongoDB.
- **Session management** is handled using tokens, with expiration policies for access control.

## How can I troubleshoot or debug the backend?

1. **Enable Debug Mode**: Set `LOGGING_LEVEL=debug` in your environment configuration.
2. **Check Logs**: Review the server logs for error messages and detailed tracebacks.
3. **Test APIs**: Use tools like **Postman** to test the API endpoints and ensure they are functioning correctly.
4. **Monitor MongoDB and Redis**: Ensure that database connections and queries are working without issues.

## What verifiable credential formats are supported?

- **JWT VC JSON**: Verifiable credentials in JSON Web Token format.
- **LDP VC**: Verifiable credentials using Linked Data Proofs.
- **SD-JWT**: A format offering selective disclosure JWT for increased privacy.

## How do I integrate with external issuers?

- You can integrate external issuers by using the API or admin dashboard.
- Provide the issuer's metadata, such as the URL, VC format, and credential type, to enable them to issue credentials to wallet users.
- Issuer settings can be configured to filter based on the selected VC format (e.g., JWT or LDP).

## How do I manage user roles and permissions?

- The Wallet Provider Backend supports **role-based access control**.
- You can define user roles (e.g., Admin, Organization, or User) and assign specific permissions for each role.
- Roles can be managed via the API or through the admin dashboard, ensuring that users have appropriate access to features based on their roles.
