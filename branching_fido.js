importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importPackage(Packages.com.ibm.security.access.user);
importMappingRule("BranchingHelper");
importMappingRule("fido_common");

IDMappingExtUtils.traceString("Entry Branching FIDO Registration");

var result= false;
var username = checkLogin();

var branchMap = {};
var mechMap = {};
var methods = []
var mechanisms = [];

[mechanisms, branchMap] = getMechanismsAndBranchMap();
state.put("decision", branchMap[mechanisms[0]]);

if(username != null) {
    result = true;
    var enrolledMethods = MechanismRegistrationHelper.getRegistrationsForUser(username, getLocale());
    for(i = 0; i < enrolledMethods.size(); i++) {
        var method = enrolledMethods.get(i);
        var uri = method.getMechURI();
        if(uri == "urn:ibm:security:authentication:asf:mechanism:fido2") {
            IDMappingExtUtils.traceString("Already enrolled in FIDO, do an assertion");
            page.setValue("/authsvc/authenticator/infomap/fido_assertion.html");
            state.put("fidoInfoMap", "assertionOptions");
            break;
        }
    }
    if(state.get("fidoInfoMap") == null) {
        IDMappingExtUtils.traceString("No enrollments. Force FIDO registration");
        page.setValue("/authsvc/authenticator/infomap/fido_attestation.html");
        state.put("fidoInfoMap", "attestationOptions");
    }
} else {
    page.setValue("/authsvc/authenticator/error.html");
    result = false;
}
success.setValue(result);
IDMappingExtUtils.traceString("Entry Branching FIDO Registration");
