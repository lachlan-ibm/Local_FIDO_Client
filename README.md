# Local FIDO Client Authentication demo

This repo contains the JavaScript InfoMap files requried to set-up the Local FIDO2 Client demonstratin for IBM Security 
Verify Access.

branching_fido.js
Branching JavaScript rule which will select FIDO2 as an authentication factor If the user is enrolled, otherwise 
Username/Password authentication is selected and if the user is successful, they are prompted to enroll a FIDO2 capable 
device.

fido2_branching_client.js
InfoMap rule which contains logic for verifying a FIDO2 registration of authentication attempt.

fido2_common.js
Common properties for demonstration scenario. Users should update this file with environment specific properties.
