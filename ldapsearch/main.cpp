#include <beacon.h>
#include <windows.h>
#include <dsgetdc.h>
#include <winldap.h>
#include <winber.h>
#include <rpc.h>
#include <lm.h>
#include <sddl.h>
#include <rpcdce.h>
#include <stdint.h>
#define SECURITY_WIN32
#include <security.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_ATTRIBUTES 100
#define PAGE_SIZE 500
#define TIMEOUT 15

void print_ldap_error(const char *location, ULONG error) {
    BeaconPrintf(CALLBACK_ERROR, "LDAP error %lu from %s: %s\n", error, location, ldap_err2string(error));
}

BOOLEAN _cdecl ServerCertCallback (PLDAP Connection, PCCERT_CONTEXT pServerCert)
{
	return TRUE;
}

//https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/ldap-server-sd-flags-oid
// Set LDAP server control flags so low-privileged domain users can read nTSecurityDescriptor attribute
PLDAPControlA FormatSDFlags(int iFlagValue) {
	BerElement *pber = NULL;
	PLDAPControl pLControl = NULL;
	PBERVAL pldctrl_value = NULL;
	int success = -1;
	// Format and encode the SEQUENCE data in a BerElement.
	pber = ber_alloc_t(LBER_USE_DER);
	if(pber==NULL) return NULL;

	pLControl = (PLDAPControl)malloc(sizeof(LDAPControl));
	if(pLControl==NULL) { 
        BeaconPrintf(CALLBACK_ERROR, "Out of memory\n");
        goto FormatSDFlags_error;
    }
	success = ber_printf(pber,(char *)"{i}",iFlagValue);
    if (success == -1) {
        BeaconPrintf(CALLBACK_ERROR, "ber_printf failed!\n");
        goto FormatSDFlags_error;
    }
	
	// Transfer the encoded data into a BERVAL.
	success = ber_flatten(pber,&pldctrl_value);
	if(success == 0) {
		ber_free(pber,1);
        pber = NULL;
    } else {
		BeaconPrintf(CALLBACK_ERROR, "ber_flatten failed!\n");
        goto FormatSDFlags_error;
	}
	// Copy the BERVAL data to the LDAPControl structure.
	pLControl->ldctl_oid = (char *) "1.2.840.113556.1.4.801";
	pLControl->ldctl_iscritical = TRUE;
	pLControl->ldctl_value.bv_val = (char*)malloc((size_t)pldctrl_value->bv_len);
    if (pLControl->ldctl_value.bv_val == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Out of memory\n");
        goto FormatSDFlags_error;
    }
	memcpy(pLControl->ldctl_value.bv_val, pldctrl_value->bv_val, pldctrl_value->bv_len);
	pLControl->ldctl_value.bv_len = pldctrl_value->bv_len;
	
	// Cleanup temporary berval.
	ber_bvfree(pldctrl_value);
    pldctrl_value = NULL;
	// Return the formatted LDAPControl data.
	return pLControl;

    // Error handler
    FormatSDFlags_error:
    if (pber != NULL) ber_free(pber, 1);
    if (pLControl != NULL) free(pLControl);
    return NULL;
    
}

// https://github.com/macosforge/dss/blob/master/CommonUtilitiesLib/base64.c
static const char basis_64[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int Base64encode(char* encoded, const char* string, int len) {
	int i;
	char* p;

	p = encoded;
	for (i = 0; i < len - 2; i += 3) {
		*p++ = basis_64[(string[i] >> 2) & 0x3F];
		*p++ = basis_64[((string[i] & 0x3) << 4) |
			((int)(string[i + 1] & 0xF0) >> 4)];
		*p++ = basis_64[((string[i + 1] & 0xF) << 2) |
			((int)(string[i + 2] & 0xC0) >> 6)];
		*p++ = basis_64[string[i + 2] & 0x3F];
	}
	if (i < len) {
		*p++ = basis_64[(string[i] >> 2) & 0x3F];
		if (i == (len - 1)) {
			*p++ = basis_64[((string[i] & 0x3) << 4)];
			*p++ = '=';
		}
		else {
			*p++ = basis_64[((string[i] & 0x3) << 4) |
				((int)(string[i + 1] & 0xF0) >> 4)];
			*p++ = basis_64[((string[i + 1] & 0xF) << 2)];
		}
		*p++ = '=';
	}

	*p++ = '\0';
	return p - encoded;
}

LDAP* InitialiseLDAPConnection(PCHAR hostName, PCHAR distinguishedName, BOOL ldaps){
	LDAP* pLdapConnection = NULL;

    ULONG result;
    int portNumber = ldaps ? 636 : 389;

    pLdapConnection = ldap_init(hostName, portNumber);
    if (pLdapConnection == NULL)
    {
        print_ldap_error("ldap_init", LdapGetLastError());
      	BeaconPrintf(CALLBACK_ERROR,"Failed to establish LDAP connection on %d.", portNumber);
        return NULL;
    }

    // Without disabling this option only the first page is returned
    result = ldap_set_optionW(pLdapConnection, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    if (result != LDAP_SUCCESS){goto handle_set_error;}

    if(ldaps){

        ULONG version = LDAP_VERSION3;

        result = ldap_set_optionW(pLdapConnection, LDAP_OPT_VERSION, (void*)&version);
        if (result != LDAP_SUCCESS){goto handle_set_error;}

        result = ldap_set_optionW(pLdapConnection, LDAP_OPT_SSL, LDAP_OPT_ON);
        if (result != LDAP_SUCCESS){goto handle_set_error;}

        result = ldap_set_optionW(pLdapConnection, LDAP_OPT_SIGN, LDAP_OPT_ON);
        if (result != LDAP_SUCCESS){goto handle_set_error;}

        result = ldap_set_optionW(pLdapConnection, LDAP_OPT_ENCRYPT, LDAP_OPT_ON);
        if (result != LDAP_SUCCESS){goto handle_set_error;}

        result = ldap_set_optionW(pLdapConnection, LDAP_OPT_SERVER_CERTIFICATE, (void*)&ServerCertCallback ); //LDAP_OPT_SERVER_CERTIFICATE
        if (result != LDAP_SUCCESS) {goto handle_set_error;}
	}
    
	//////////////////////////////
	// Bind to DC
	//////////////////////////////
    result = ldap_bind_s(
                pLdapConnection,      // Session Handle
                distinguishedName,    // Domain DN
                NULL,                 // Credential structure
                LDAP_AUTH_NEGOTIATE); // Auth mode

    if(result != LDAP_SUCCESS)
    {
    	BeaconPrintf(CALLBACK_ERROR, "Bind Failed\n");
        print_ldap_error("ldap_bind_s",result);
        ldap_unbind(pLdapConnection);
        pLdapConnection = NULL; 
    }
    return pLdapConnection;
handle_set_error:
    BeaconPrintf(CALLBACK_ERROR, "LDAPS connection failed\n");
    print_ldap_error("ldap_set_optionW", result);
    ldap_unbind(pLdapConnection);
    return NULL;
}

void InitAttributes(char *ldap_attributes, PCHAR *attr, PLDAPControlA *serverControls) {
	int sdFlags = 0x07;
	if(ldap_attributes){
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Returning specific attribute(s): %s\n",ldap_attributes);
        
        int attribute_count = 0;
        char *token = NULL;
        const char s[2] = ","; //delimiter

        token = strtok(ldap_attributes, s);

        while( token != NULL ) {
			if (_stricmp(token, "nTSecurityDescriptor") == 0) {
				serverControls[1] = FormatSDFlags(sdFlags);
				serverControls[2] = NULL;
			}
            if(attribute_count < (MAX_ATTRIBUTES - 1)){
                attr[attribute_count] = token;
                attribute_count++;
                token = strtok(NULL, s);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Cannot return more than %i attributes, will omit additional attributes.\n", MAX_ATTRIBUTES);
                break;
            }
        }
    }
}

void customAttributes(PCHAR pAttribute, PBERVAL pValue)
{
    if(strcmp(pAttribute, "objectGUID") == 0) 
    {
        RPC_CSTR G = NULL;
        RPC_STATUS status = UuidToStringA((UUID *) pValue->bv_val, &G);
        if (status != RPC_S_OK) {
            BeaconPrintf(CALLBACK_ERROR, "Out of memory\n");
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "%s", G);
        RpcStringFreeA(&G);
    } else if ( strcmp(pAttribute, "attributeSecurityGUID") == 0 
             || strcmp(pAttribute, "auditingPolicy") == 0 
             || strcmp(pAttribute, "authorityRevocationList") == 0 
             || strcmp(pAttribute, "cACertificate") == 0 
             || strcmp(pAttribute, "certificateRevocationList") == 0 
             || strcmp(pAttribute, "dSASignature") == 0 
             || strcmp(pAttribute, "logonHours") == 0 
             || strcmp(pAttribute, "mS-DS-CreatorSID") == 0 
             || strcmp(pAttribute, "mSMQDigests") == 0 
             || strcmp(pAttribute, "mSMQSignCertificates") == 0 
             || strcmp(pAttribute, "msDS-AllowedToActOnBehalfOfOtherIdentity") == 0 
             || strcmp(pAttribute, "msDS-GenerationId") == 0 
             || strcmp(pAttribute, "nTSecurityDescriptor") == 0 
             || strcmp(pAttribute, "pKIExpirationPeriod") == 0 
             || strcmp(pAttribute, "pKIKeyUsage") == 0 
             || strcmp(pAttribute, "pKIOverlapPeriod") == 0 
             || strcmp(pAttribute, "schemaIDGUID") == 0 
             || strcmp(pAttribute, "userCertificate") == 0
             || strcmp(pAttribute, "mS-DS-ConsistencyGuid") == 0
             || strcmp(pAttribute, "msExchSafeSendersHash") == 0
    ) {
		char *encoded = NULL;
		ULONG len = pValue->bv_len;
		encoded = (char *)malloc((size_t)len*2);
        if (encoded == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "Out of memory\n");
            return;
        }
		Base64encode(encoded, (char *)pValue->bv_val, len);
		BeaconPrintf(CALLBACK_OUTPUT, "%s", encoded);
		free(encoded);
	}
    else if(strcmp(pAttribute, "objectSid") == 0 || strcmp(pAttribute, "securityIdentifier") == 0)
    {
        LPSTR sid = NULL;
        BOOL success = ConvertSidToStringSidA((PSID)pValue->bv_val, &sid);
        if (!success) {
            BeaconPrintf(CALLBACK_ERROR, "Converting SID to string failed\n");
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "%s", sid);
        if (sid != NULL) LocalFree(sid);
    }
    else
    {
        //The strings are not always NULL-terminated, so limit the length
        BeaconPrintf(CALLBACK_OUTPUT, "%.*s", pValue->bv_len, pValue->bv_val);
    }
    
}

void printAttribute(PCHAR pAttribute, PBERVAL *ppValue){
    BeaconPrintf(CALLBACK_OUTPUT, "\n%s: ", pAttribute);
    customAttributes(pAttribute, *ppValue);
    ppValue++;
    while(*ppValue != NULL)
    {
        BeaconPrintf(CALLBACK_OUTPUT, ", ");
        customAttributes(pAttribute, *ppValue);
        ppValue++;
    }
}

void ldapSearch(char * ldap_filter, char * ldap_attributes,	ULONG results_count, ULONG scope_of_search, char * hostname, char * domain, BOOL ldaps){
    char szDN[1024] = {0};
	ULONG ulSize = sizeof(szDN)/sizeof(szDN[0]);
	
    DWORD dwRet = 0;
    PDOMAIN_CONTROLLER_INFO pdcInfo = NULL;
    LDAP* pLdapConnection = NULL; 
    PLDAPMessage pSearchResult = NULL;
    char* distinguishedName = NULL;
    char * targetdc = NULL;
    BerElement* pBer = NULL;
    LDAPMessage* pEntry = NULL;
    PCHAR pEntryDN = NULL;
    PCHAR pAttribute = NULL;
    PBERVAL* ppValue = NULL;
    ULONG results_limit = 0;
    ULONG totalResults = 0;
    ULONG error = NULL;

    if (domain) {
        distinguishedName = domain;
    } else {
        BOOL res = GetUserNameExA(NameFullyQualifiedDN, szDN, &ulSize);
        if (res) {
        	distinguishedName = strstr(szDN, "DC=");
        } else {
    		BeaconPrintf(CALLBACK_ERROR, "Failed to retrieve distinguished name.");
            goto end;
        }
    }
	BeaconPrintf(CALLBACK_OUTPUT, "[*] Distinguished name: %s\n", distinguishedName);	

	////////////////////////////
	// Retrieve PDC
	////////////////////////////
    

    if (hostname) {
        targetdc = hostname;
    } else {
        dwRet = DsGetDcNameA(NULL, NULL, NULL, NULL, 0, &pdcInfo);
        if (ERROR_SUCCESS == dwRet) {
            targetdc = pdcInfo->DomainControllerName + 2;
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Failed to identify PDC, are we domain joined?");
            goto end;
        }
    }
    if(pdcInfo != NULL)
    {
        NetApiBufferFree(pdcInfo);
        pdcInfo = NULL;
    }

	//////////////////////////////
	// Initialise LDAP Session
    // Taken from https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/searching-a-directory
	//////////////////////////////
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Binding to %s\n", targetdc);
    pLdapConnection = InitialiseLDAPConnection(targetdc, distinguishedName, ldaps);

    if(!pLdapConnection)
        {goto end;}

	//////////////////////////////
	// Perform LDAP Search
	//////////////////////////////
    PLDAPControlA serverControls[3] = {0};
    PLDAPControlA *returnedControls = NULL;
    LDAP_TIMEVAL timeout = {TIMEOUT, 0};
    PCHAR attr[MAX_ATTRIBUTES] = {0};
    InitAttributes(ldap_attributes, attr, serverControls);
    ULONG returnCode = LDAP_SUCCESS;
    DWORD numberOfEntries = 0;
    PBERVAL cookie = NULL;
    PLDAPMessage message = NULL;
    BOOL moreResults = TRUE;
    BOOL done = FALSE;
    ULONG page_size = PAGE_SIZE;
    if (results_count > 0 && results_count < PAGE_SIZE) {
        page_size = results_count;
    }
    do
    {
        error = ldap_create_page_control(pLdapConnection, page_size, cookie, FALSE, &serverControls[0]);
        if (error != LDAP_SUCCESS) {
            print_ldap_error("ldap_create_page_control", error);
            goto end;
        }

    	error = ldap_search_ext_s(
        	pLdapConnection,                     // Session handle
        	distinguishedName,                   // DN to start search
        	scope_of_search,                     // Scope
        	ldap_filter,                         // Filter
        	(*attr) ? attr : NULL,               // Retrieve list of attributes
        	0,                                   // Get both attributes and values
        	serverControls,
        	NULL,
        	&timeout,
        	results_count,
        	&message);

        if (error != LDAP_SUCCESS)
        {
            print_ldap_error("ldap_search_ext_s", error);
            goto end;
        }

        error = ldap_parse_result(pLdapConnection, message, &returnCode, NULL, NULL, NULL, &returnedControls, FALSE);
        if (error != LDAP_SUCCESS) {
            print_ldap_error("ldap_parse_result", error);
            goto end;
        }
        if (returnCode != LDAP_SUCCESS) {
            print_ldap_error("LDAP search", returnCode);
            goto end;
        }

        if (serverControls[0] != NULL) {
            ldap_control_free(serverControls[0]);
            serverControls[0] = NULL;
        }

        if (cookie != NULL) {
            ber_bvfree(cookie);
            cookie = NULL;
        }

        error = ldap_parse_page_control(pLdapConnection, returnedControls, &numberOfEntries, &cookie);
        if (error != LDAP_SUCCESS) {
            print_ldap_error("ldap_parse_page_control", error);
            goto end;
        }
        if (returnedControls != NULL) {
            ldap_controls_free(returnedControls);
            returnedControls = NULL;
        }

        moreResults = cookie != NULL && cookie->bv_val != NULL && cookie->bv_len > 0;

        if (numberOfEntries == 0) {
            numberOfEntries = ldap_count_entries(pLdapConnection, message);
        
            if(numberOfEntries == -1)
            {
                BeaconPrintf(CALLBACK_ERROR, "Failed to count search results.");
                goto end;
            }
        }
        
        totalResults += numberOfEntries;
        done = totalResults >= results_count && results_count != 0;

        for( pEntry = ldap_first_entry(pLdapConnection, message); 
             pEntry != NULL; 
             pEntry = ldap_next_entry(pLdapConnection, pEntry))
        {
            BeaconPrintf(CALLBACK_OUTPUT, "\n--------------------");

            // Output the attribute names for the current object
            // and output values.
            for (
                pAttribute = ldap_first_attribute(pLdapConnection, pEntry, &pBer);         
                pAttribute != NULL;
                pAttribute = ldap_next_attribute(pLdapConnection, pEntry, pBer)           
            )
            {
                ppValue = ldap_get_values_lenA(pLdapConnection, pEntry, pAttribute);
                if (ppValue == NULL) {
                    error = LdapGetLastError();
                    if (error != LDAP_SUCCESS) {
                        print_ldap_error("ldap_get_values_lenA", error);
                        goto end;
                    }
                } else {
                    printAttribute(pAttribute, ppValue);
                    ldap_value_free_len((PBERVAL *)ppValue);
                    ppValue = NULL;
                }
                ldap_memfree(pAttribute);
                
            }

            //pAttribute is NULL, there could have been an error
            error = LdapGetLastError();
            if (error != LDAP_SUCCESS) {
                print_ldap_error("pAttribute", error);
                goto end;
            }
            
            if( pBer != NULL )
            {
                ber_free(pBer,0);
                pBer = NULL;
            }
        }

        if (message != NULL) {
            ldap_msgfree(message); 
            message = NULL;
        }

    }while(moreResults && !done);

    end: 
    BeaconPrintf(CALLBACK_OUTPUT, "\nretrieved %lu results total\n", totalResults);
    if (ppValue)
    {
        ldap_value_free_len((PBERVAL *)ppValue);
        ppValue = NULL;
    }    
    if (pAttribute)
    {
        ldap_memfree(pAttribute);
    }
    if (cookie != NULL) {
        ber_bvfree(cookie);
        cookie = NULL;
    }
    if (message != NULL) {
        ldap_msgfree(message);
        message = NULL;
    }
    if (serverControls[0]) ldap_control_free(serverControls[0]);
    if (serverControls[1]) {
		free(serverControls[1]->ldctl_value.bv_val);
		free(serverControls[1]);
    }
    if (returnedControls != NULL) {
        ldap_controls_free(returnedControls);
        returnedControls = NULL;
    }
    if( pBer != NULL )
    {
        ber_free(pBer,0);
        pBer = NULL;
    }
    if(pdcInfo)
    {
        NetApiBufferFree(pdcInfo);
        pdcInfo = NULL;
    }
    if(pLdapConnection)
    {
        ldap_unbind(pLdapConnection);
        pLdapConnection = NULL;
    }

}

extern "C" __declspec(dllexport) void go(const char* Buffer, int Length){

    //This takes care of initializing the C runtime if needed
    BEACON_INIT;
    
	datap  parser;
	char * ldap_filter;
	char * ldap_attributes;
    char * hostname;
    char * domain;
	ULONG results_count;
    ULONG scope_of_search;
    ULONG ldaps;

	BeaconDataParse(&parser, (char *)Buffer, Length);
	ldap_filter = BeaconDataExtract(&parser, NULL);
	ldap_attributes = BeaconDataExtract(&parser, NULL);
	results_count = BeaconDataInt(&parser);
	scope_of_search = BeaconDataInt(&parser);
    hostname = BeaconDataExtract(&parser, NULL);
    domain = BeaconDataExtract(&parser, NULL);
    ldaps = BeaconDataInt(&parser);

    ldap_attributes = *ldap_attributes == 0 ? NULL : ldap_attributes;
    hostname = *hostname == 0 ? NULL : hostname;
    domain = *domain == 0 ? NULL : domain;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Filter: %s\n",ldap_filter);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scope of search value: %lu\n",scope_of_search);

    if (scope_of_search == 1){
        scope_of_search = LDAP_SCOPE_BASE;
    } 
    else if (scope_of_search == 2){
        scope_of_search = LDAP_SCOPE_ONELEVEL;
    }
    else if (scope_of_search == 3){
        scope_of_search = LDAP_SCOPE_SUBTREE;
    }

	ldapSearch(ldap_filter, ldap_attributes, results_count, scope_of_search, hostname, domain, ldaps==1);

}

//A helper macro that will declare main inside the .discard section
//and invoke BeaconInvokeStandalone with the expected packed argument format  
BEACON_MAIN("zziizzi", go)
