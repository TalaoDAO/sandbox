# Manage Users

Updated the 8th of March 2025.

From the main dashboard, you can manage an Access Control List (ACL): add or desactivate users, add new admins and access to the QR code page and installation link or open the wallet to the public with guest.

## User, admin and guest

There are 3 types of actors:

* user (optional): they are referenced in the data base (ACL) and they will need a login/password to onboard the wallet with the configuration,
* admin: they have an access to the main dashboard of the wallet provider backend, they are referenced in the data base,
* guest (optional): they are not referenced in the database, they can download the wallet and use it with a configuration.

When you add a user or an admin you will enter his email, first name and last name. At creation the user will receive an email with an invitation link to a QR code page to configure his wallet. He will also receive a password to connect directly to his account on the Wallet Provider Backend.

User can connect to the backend through a link like [https://wallet-provider.talao.co/users](https://wallet-provider.talao.co/users) . The link could be different if you have a customized instance of the Wallet Provider Backend.

At creation an organization has one admin and one guest. You dont need more than one guest as the QR code to cionfigure the wallet is the same for all guests. **The guest QR code is the best way to publish the wallet configuration to a wide public.** The guest can be deleted to limit the use of the wallet to the ACL.

When you clic on the user you have an access to a screen with his personal information. You can there send a new password to the user or even desactivate the user. A user desactivated will not be able to get the configuration or the updates of the configuration. A user desactivated can be reactivated later.

When you clic on the guest you have access to the guest QR code and the guest installation link. The QR code and link are statics. They can be reused multiple times.

To start the customizations of the wallets clic on "Start customizing your wallet".
