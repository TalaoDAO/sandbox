# User support

Updated the 14th of October 2024.

## Chat and Notification for wallet users with Matrix

[Matrix.org](https://matrix.org/) is an open-source, decentralized, end-to-end encrypted messaging protocol. Unlike centralized services such as WhatsApp, Slack, or Telegram, Matrix ensures privacy and avoids using private, centralized services. Currently, there are over 1,000 Matrix servers. Talao operates its own server, dedicated to the authentication of its wallets

For more information about Matrix, you can visit:

- [Matrix Clients](https://matrix.org/ecosystem/clients/)
- [Matrix Servers](https://servers.joinmatrix.org/)

There are many Matrix client applications available. You can find a list [here](https://matrix.org/ecosystem/clients/).

We recommend using the [Element Client](https://matrix.org/ecosystem/clients/element/), which is one of the most popular options. Element is available on iOS and Android smartphones, as well as on various web platforms like Windows and Linux. You can download it from this [Element page](https://matrix.org/ecosystem/clients/element/).

To configure Chat and Notification with Element, follow the 3 steps below:

### Step 1: Creating an Account for Chat

Once you install the Element client, create an account on a public server, such as [matrix.org](https://matrix.org), or any other public server. You can view a list of available servers [here](https://servers.joinmatrix.org/). After completing this step, you will have a chat address in the format `@my_name:matrix.org`, assuming you use the matrix.org server.

### Step 2: Creating a Public Room for Notifications

In Element, select the option to create a **public** room, and enter a name for your room. If you use the matrix.org server, you will receive a room address in the format `#my_room:matrix.org`. Please ensure that the room is set to "public," not "private."

### Step 3: Entering Information on the Wallet Provider Backend

In the wallet provider backend, go to the **Support** page and enter your chat and notification identifier in forms **7.2** and **7.5**. Save the configuration.

The chat account identifier starts with "@", exemple `@support:matrix.org`, the room identifier starts with "#" example`#room:matrix.org`.

## Using Chat and Notifications

- **For Chat**: You will receive an invitation in your Element client app from each wallet using your configuration. Accept the invitation, and you can privately and anonymously communicate with the wallet user in a private room. All messages are end-to-end encrypted, and you can exchange both text and images.
- **For Notifications**: Any messages you post in your notification room will be sent to all wallets. Note that users cannot reply to these messages.
