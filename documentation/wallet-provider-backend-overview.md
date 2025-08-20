# Overview

Updated the 15th of October 2024.

The Wallet Provider Backend is a web application for managing the wallets that an organization makes available to its employees or users.

This application allows advanced customization of the wallet, whether in terms of branding or technical parameters, choice of attestation formats and issuers available directly in the wallet. The Wallet Provider Backend also allows fine management of users and their wallets (revocation, suspension, etc.). The Wallet Provider Backend is based on the ARF architecture and issues in particular the Wallet Instance Attestation (WIA) which certifies the origin of the wallet and the cryptographic material used (Trust Chain).

This application is installed on an AWS server in Europe.

With the wallet provider backend it is possible to customize the wallet and in particular:

- create organizations or projects of wallet users,
- add or suspend users in an organization,
- adapt the look and feel (branding) of the mobile app,
- simplify the interface of the app to hide the features that are useless for the use case,
- customize the technical parameters of the wallet app to the ecosystem profile (EBSI, ARF, DIIP, ...),
- get QR codes to configure a wallet and get installation links to download and configure wallets in one step,
- add issuers links embedded in the wallet app,
- use chat and notification services to support and communicate with users.

After defining a configuration in the web application it is possible to configure the wallet by scanning a QR code with the app camera.

The Wallet Provider Backend is offered in the form of a commercial license, it is useful for a complex configuration of the wallet or for the deployment of projects.

To open an account to test the Wallet Provider Backend send us an email to [contact@talao.io](mailto:contact@talao.io).
