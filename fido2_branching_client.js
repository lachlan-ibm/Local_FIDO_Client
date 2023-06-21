/*********************************************************************
 *   Licensed Materials - Property of IBM
 *   (C) Copyright IBM Corp. 2023. All Rights Reserved
 *********************************************************************/

importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("fido_common");
var rc = false;

// Change this to the ID if your Relying Party
fido_client = fido2ClientManager.getClient(FIDO_RP_ID);

function requestParam(key) {
    var value = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", key);
    return (value == null) ? null : ''+value;
}

function getUsernameFromSession() {
    var username = ''+context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username");
    return username;
}

// We expect the parameter fidoInfoMap in the request with a value of
// attestationOptions, attestationResult, assertionOptions or assertionResult
var fidoInfoMap = state.get("fidoInfoMap");

if (fidoInfoMap == "attestationOptions") {
    var options = JSON.parse(fido_client.attestationOptions('{"username":"' + getUsernameFromSession() +'"}'));
    IDMappingExtUtils.traceString(JSON.stringify(options));
    var status = options['status'];
    if (status == 'ok') {
        macros.put("@FIDO_RP_ID@", options['rp']['id']);
        macros.put("@FIDO_RP_NAME@", options['rp']['name']);
        macros.put("@FIDO_TIMEOUT@", options['timeout'].toString());
        macros.put("@FIDO_CHALLENGE@", options['challenge']);
        macros.put('@FIDO_EXTENSIONS@', JSON.stringify(options['extensions']));
        var authenticatorSelection = options['authenticatorSelection']
        if (authenticatorSelection != null) {
            macros.put("@FIDO_AUTHENTICATOR_SELECTION@", JSON.stringify(authenticatorSelection));
        }
        var attestation = options['attestation']
        if (attestation != null) {
            macros.put("@FIDO_ATTESTATION@", attestation);
        }
        macros.put("@FIDO_USER_ID@", options['user']['id']);
        macros.put("@FIDO_USER_NAME@", options['user']['name']);
        macros.put("@FIDO_USER_DISPLAY_NAME@", options['user']['displayName']);
        macros.put("@FIDO_STATUS@", options['status']);
        macros.put("@FIDO_ERROR_MESSAGE@", options['errorMessage']);
        var pubKeyCredParams = options['pubKeyCredParams'];
        macros.put("@FIDO_PUBKEY_CRED_PARAMS@", JSON.stringify( pubKeyCredParams));
        var excludeCredentials = options['excludeCredentials'];
        macros.put("@FIDO_EXCLUDED_CREDENTIALS@", JSON.stringify( excludeCredentials));
        macros.put("@FIDO_INFOMAP_PARAM@", "&fidoInfoMap=attestationResult");
        page.setValue('/authsvc/authenticator/infomap/fido_attestation.html');
        state.put("fidoInfoMap", "attestationResult");
    } else {
        macros.put("@ERROR_MESSAGE@", options['errorMessage']);
        page.setValue('/authsvc/authenticator/fido/error.html');
    }

}
else if (fidoInfoMap == "attestationResult") {
    var attestation = {
                    'type': requestParam("type"),
                    'id': requestParam("id"),
                    'rawId': requestParam("rawId"),
                    'response': {
                        'clientDataJSON': requestParam("clientDataJSON"),
                        'attestationObject': requestParam("attestationObject")
                    },
    };
    var clientExtensionResults = requestParam("getClientExtensionResults");
    if (clientExtensionResults != null) {
        attestation['getClientExtensionResults'] = JSON.parse(clientExtensionResults);
    }
    IDMappingExtUtils.traceString("attestation: " + JSON.stringify(attestation));
    var result = JSON.parse(fido_client.attestationResult( JSON.stringify(attestation)));
    var status = result['status'];
    if (status == 'ok') {
        rc= true;
    } else {
        macros.put( "@ERROR_MESSAGE@", result['errorMessage']);
        page.setValue('/authsvc/authenticator/fido/error.html');
    }
    

}
else if (fidoInfoMap == "assertionOptions") {
    var options = JSON.parse(fido_client.assertionOptions('{"username":"' + getUsernameFromSession() +'"}'));
    IDMappingExtUtils.traceString(JSON.stringify(options));
    var status = options['status'];
    if (status == 'ok') {
        macros.put("@FIDO_RP_ID@", options['rpId']);
        macros.put("@FIDO_TIMEOUT@", options['timeout'].toString());
        macros.put("@FIDO_CHALLENGE@", options['challenge']);
        macros.put('@FIDO_EXTENSIONS@', JSON.stringify( options['extensions']));
        macros.put("@FIDO_USER_ID@", options['userId']);
        macros.put("@FIDO_STATUS@", options['status']);
        macros.put("@FIDO_ERROR_MESSAGE@", options['errorMessage']);
        macros.put("@FIDO_ALLOW_CREDENTIALS@", JSON.stringify(options['allowCredentials']));
        macros.put("@FIDO_INFOMAP_PARAM@", "&fidoInfoMap=assertionResult");
        page.setValue('/authsvc/authenticator/infomap/fido_assertion.html');
        state.put("fidoInfoMap", "assertionResult");
    } else {
        macros.put("@ERROR_MESSAGE@", options['errorMessage']);
        page.setValue('/authsvc/authenticator/fido/error.html');
    }
}
else if (fidoInfoMap == "assertionResult") {
    var assertion = {
                    'type': requestParam("type"),
                    'id': requestParam("id"),
                    'rawId': requestParam("rawId"),
                    'response': {
                        'clientDataJSON': requestParam("clientDataJSON"),
                        'authenticatorData': requestParam("authenticatorData"),
                        'signature': requestParam("signature"),
                        'userHandle': requestParam("userHandle")
                    },
    };
    var clientExtensionResults = requestParam("getClientExtensionResults");
    if (clientExtensionResults != null) {
        assertion['getClientExtensionResults'] = JSON.parse(clientExtensionResults);
    }
    IDMappingExtUtils.traceString("assertion: " + JSON.stringify(assertion));
    var result = JSON.parse(fido_client.assertionResult(JSON.stringify(assertion)));
    var status = result['status'];
    if (status == 'ok') {
        rc= true;
    } else {
        macros.put("@ERROR_MESSAGE@", result['errorMessage']);
        page.setValue('/authsvc/authenticator/fido/error.html');
    }

} else {
    macros.put("@ERROR_MESSAGE@", 'expected parameter "fidoInfoMap" in request');
    page.setValue('/authsvc/authenticator/fido/error.html'); 
}

success.setValue(rc);
