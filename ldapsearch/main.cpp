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
	if(pLControl==NULL) { ber_free(pber,1); return NULL; }
	ber_printf(pber,(char *)"{i}",iFlagValue);
	
	// Transfer the encoded data into a BERVAL.
	success = ber_flatten(pber,&pldctrl_value);
	if(success == 0)
		ber_free(pber,1);
	else {
		BeaconPrintf(CALLBACK_ERROR, "ber_flatten failed!");
		// Call error handler here.
	}
	// Copy the BERVAL data to the LDAPControl structure.
	pLControl->ldctl_oid = (char *) "1.2.840.113556.1.4.801";
	pLControl->ldctl_iscritical = TRUE;
	pLControl->ldctl_value.bv_val = (char*)malloc((size_t)pldctrl_value->bv_len);
	memcpy(pLControl->ldctl_value.bv_val, pldctrl_value->bv_val, pldctrl_value->bv_len);
	pLControl->ldctl_value.bv_len = pldctrl_value->bv_len;
	
	// Cleanup temporary berval.
	ber_bvfree(pldctrl_value);
	// Return the formatted LDAPControl data.
	return pLControl;
}

// https://opensource.apple.com/source/QuickTimeStreamingServer/QuickTimeStreamingServer-452/CommonUtilitiesLib/base64.c.auto.html
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
    int portNumber = ldaps == TRUE ? 636 : 389;

    pLdapConnection = ldap_init(hostName, portNumber);

    if(ldaps == TRUE){

        ULONG version = LDAP_VERSION3;
        result = ldap_set_optionW(pLdapConnection, LDAP_OPT_VERSION, (void*)&version);
    
        ldap_get_optionW(pLdapConnection, LDAP_OPT_SSL, &result);  //LDAP_OPT_SSL
        if (result == 0){
            ldap_set_optionW(pLdapConnection, LDAP_OPT_SSL, LDAP_OPT_ON);
        }

        ldap_get_optionW(pLdapConnection, LDAP_OPT_SIGN, &result);  //LDAP_OPT_SIGN
        if (result == 0){
            ldap_set_optionW(pLdapConnection, LDAP_OPT_SIGN, LDAP_OPT_ON);
        }

        ldap_get_optionW(pLdapConnection, LDAP_OPT_ENCRYPT, &result);  //LDAP_OPT_ENCRYPT
        if (result == 0){
            ldap_set_optionW(pLdapConnection, LDAP_OPT_ENCRYPT, LDAP_OPT_ON);
        }

        ldap_set_optionW(pLdapConnection, LDAP_OPT_SERVER_CERTIFICATE, (void*)&ServerCertCallback ); //LDAP_OPT_SERVER_CERTIFICATE
	}
    
    if (pLdapConnection == NULL)
    {
      	BeaconPrintf(CALLBACK_ERROR,"Failed to establish LDAP connection on %d.", portNumber);
        return NULL;
    }
    //ldap_set_optionA(pLdapConnection, LDAP_OPT_VERSION,&Version );

	//////////////////////////////
	// Bind to DC
	//////////////////////////////
    ULONG lRtn = 0;

    lRtn = ldap_bind_s(
                pLdapConnection,      // Session Handle
                distinguishedName,    // Domain DN
                NULL,                 // Credential structure
                LDAP_AUTH_NEGOTIATE); // Auth mode

    if(lRtn != LDAP_SUCCESS)
    {
    	BeaconPrintf(CALLBACK_ERROR, "Bind Failed: %lu", lRtn);
        ldap_unbind(pLdapConnection);
        pLdapConnection = NULL; 
    }
    return pLdapConnection;
}

PLDAPSearch ExecuteLDAPQuery(LDAP* pLdapConnection, PCHAR distinguishedName, char * ldap_filter, char * ldap_attributes, ULONG maxResults, ULONG scope_of_search){
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Filter: %s\n",ldap_filter);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scope of search value: %lu\n",scope_of_search);

	// Security descriptor flags to read nTSecurityDescriptor as low-priv domain user
	// value taken from https://github.com/fortalice/pyldapsearch/blob/main/pyldapsearch/__main__.py (Microsoft docs mentioned XORing all possible values to get this, but that didn't work)
	int sdFlags = 0x07;
	PLDAPControlA serverControls[2];
	int aclSearch = 0;
    ULONG scope;

    ULONG errorCode = LDAP_SUCCESS;
    PLDAPSearch pSearchResult = NULL;
    PCHAR attr[MAX_ATTRIBUTES] = {0};
	if(ldap_attributes){
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Returning specific attribute(s): %s\n",ldap_attributes);
        
        int attribute_count = 0;
        char *token = NULL;
        const char s[2] = ","; //delimiter

        token = strtok(ldap_attributes, s);

        while( token != NULL ) {
			if (_stricmp(token, "nTSecurityDescriptor") == 0) {
				serverControls[0] = FormatSDFlags(sdFlags);
				serverControls[1] = NULL;
				aclSearch = 1;
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

    if (scope_of_search == 1){
        scope = LDAP_SCOPE_BASE;
    } 
    else if (scope_of_search == 2){
        scope = LDAP_SCOPE_ONELEVEL;
    }
    else if (scope_of_search == 3){
        scope = LDAP_SCOPE_SUBTREE;
    }
    

   	if (aclSearch) {
		pSearchResult = ldap_search_init_pageA(
		pLdapConnection,    // Session handle
		distinguishedName,  // DN to start search
		scope, // Scope
		ldap_filter,        // Filter
		(*attr) ? attr : NULL,               // Retrieve list of attributes
		0,                  // Get both attributes and values
		serverControls,
		NULL,
		15,
		maxResults,
		NULL);    // [out] Search results
		
		free(serverControls[0]->ldctl_value.bv_val);
		free(serverControls[0]);
	} else {
		pSearchResult = ldap_search_init_pageA(
		pLdapConnection,    // Session handle
		distinguishedName,  // DN to start search
		scope, // Scope
		ldap_filter,        // Filter
		(*attr) ? attr : NULL,               // Retrieve list of attributes
		0,                  // Get both attributes and values
		NULL,
		NULL,
		15,
		maxResults,
		NULL);    // [out] Search results
	}
    
    if (pSearchResult == NULL) 
    {
        BeaconPrintf(CALLBACK_ERROR, "Paging not supported on this server, aborting");
    }
    return pSearchResult;

}

void customAttributes(PCHAR pAttribute, PCHAR pValue)
{
    if(strcmp(pAttribute, "objectGUID") == 0) 
    {
        RPC_CSTR G = NULL;
        PBERVAL tmp = (PBERVAL)pValue;
        //UuidToStringA((UUID *) tmp->bv_val, &G);
        UuidToStringA((UUID *) tmp->bv_val, &G);
        BeaconPrintf(CALLBACK_OUTPUT, "%s", G);
        RpcStringFreeA(&G);
    } else if (strcmp(pAttribute, "pKIExpirationPeriod") == 0 
            || strcmp(pAttribute, "pKIOverlapPeriod") == 0 
            || strcmp(pAttribute, "cACertificate") == 0 
            || strcmp(pAttribute, "nTSecurityDescriptor") == 0 
            || strcmp(pAttribute, "msDS-AllowedToActOnBehalfOfOtherIdentity") == 0 
            || strcmp(pAttribute, "msDS-GenerationId") == 0 
            || strcmp(pAttribute, "auditingPolicy") == 0 
            || strcmp(pAttribute, "dSASignature") == 0 
            || strcmp(pAttribute, "mS-DS-CreatorSID") == 0 
            || strcmp(pAttribute, "logonHours") == 0 
            || strcmp(pAttribute, "schemaIDGUID") == 0 
            || strcmp(pAttribute, "mSMQDigests") == 0 
            || strcmp(pAttribute, "mSMQSignCertificates") == 0 
            || strcmp(pAttribute, "userCertificate") == 0 
            || strcmp(pAttribute, "attributeSecurityGUID") == 0  
    ) {
		char *encoded = NULL;
		PBERVAL tmp = (PBERVAL)pValue;
		ULONG len = tmp->bv_len;
		encoded = (char *)malloc((size_t)len*2);
		Base64encode(encoded, (char *)tmp->bv_val, len);
		BeaconPrintf(CALLBACK_OUTPUT, "%s", encoded);
		free(encoded);
	}
    else if(strcmp(pAttribute, "objectSid") == 0 || strcmp(pAttribute, "securityIdentifier") == 0)
    {
        LPSTR sid = NULL;
		//BeaconPrintf(CALLBACK_OUTPUT, "len of objectSID: %d\n", strlen(pValue));
        PBERVAL tmp = (PBERVAL)pValue;
        ConvertSidToStringSidA((PSID)tmp->bv_val, &sid);
        BeaconPrintf(CALLBACK_OUTPUT, "%s", sid);
        LocalFree(sid);
    }
    else
    {
        BeaconPrintf(CALLBACK_OUTPUT, "%s", pValue);
    }
    
}

void printAttribute(PCHAR pAttribute, PCHAR* ppValue){
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

void print_ldap_error(ULONG error) {
    BeaconPrintf(CALLBACK_ERROR, "LDAP error %lu: %s\n", error, ldap_err2string(error));
}

void ldapSearch(char * ldap_filter, char * ldap_attributes,	ULONG results_count, ULONG scope_of_search, char * hostname, char * domain, BOOL ldaps){
    char szDN[1024] = {0};
	ULONG ulSize = sizeof(szDN)/sizeof(szDN[0]);
	
    DWORD dwRet = 0;
    PDOMAIN_CONTROLLER_INFO pdcInfo = NULL;
    LDAP* pLdapConnection = NULL; 
    PLDAPSearch pPageHandle = NULL;
    PLDAPMessage pSearchResult = NULL;
    char* distinguishedName = NULL;
    char * targetdc = NULL;
    BerElement* pBer = NULL;
    LDAPMessage* pEntry = NULL;
    PCHAR pEntryDN = NULL;
    LDAP_TIMEVAL timeout = {20, 0};
    ULONG iCnt = 0;
    PCHAR pAttribute = NULL;
    PCHAR* ppValue = NULL;
    ULONG results_limit = 0;
    BOOL isbinary = FALSE;
    ULONG stat = 0;
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
	pPageHandle = ExecuteLDAPQuery(pLdapConnection, distinguishedName, ldap_filter, ldap_attributes, results_count, scope_of_search);   
    if (pPageHandle == NULL)
        {goto end;}
    ULONG pagecount = 0;
    do
    {
        stat = ldap_get_next_page_s(pLdapConnection, pPageHandle, &timeout, (results_count && ((results_count - totalResults) < 64))  ? results_count - totalResults : 64, &pagecount,&pSearchResult );
        if(!(stat == LDAP_SUCCESS || stat == LDAP_NO_RESULTS_RETURNED))
            {goto end;}

        if (pSearchResult == NULL) {
            continue;
        }

        //////////////////////////////
        // Get Search Result Count
        //////////////////////////////
        DWORD numberOfEntries = ldap_count_entries(
                            pLdapConnection,    // Session handle
                            pSearchResult);     // Search result
        
        if(numberOfEntries == -1) // -1 is functions return value when it failed
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to count search results.");
            goto end;
        }
        
        totalResults += numberOfEntries;

        for( pEntry = ldap_first_entry(pLdapConnection, pSearchResult); 
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
                isbinary = FALSE;
                // Get the string values.
                if(strcmp(pAttribute, "pKIExpirationPeriod") == 0 
                || strcmp(pAttribute, "pKIOverlapPeriod") == 0 
                || strcmp(pAttribute, "cACertificate") == 0 
                || strcmp(pAttribute, "objectSid") == 0 
                || strcmp(pAttribute, "securityIdentifier") == 0 
                || strcmp(pAttribute, "objectGUID") == 0 
                || strcmp(pAttribute, "nTSecurityDescriptor") == 0 
                || strcmp(pAttribute, "msDS-GenerationId") == 0 
                || strcmp(pAttribute, "auditingPolicy") == 0 
                || strcmp(pAttribute, "dSASignature") == 0 
                || strcmp(pAttribute, "mS-DS-CreatorSID") == 0 
                || strcmp(pAttribute, "logonHours") == 0 
                || strcmp(pAttribute, "schemaIDGUID") == 0 
                || strcmp(pAttribute, "msDS-AllowedToActOnBehalfOfOtherIdentity") == 0 
                || strcmp(pAttribute, "msDS-GenerationId") == 0 
                || strcmp(pAttribute, "mSMQDigests") == 0 
                || strcmp(pAttribute, "mSMQSignCertificates") == 0 
                || strcmp(pAttribute, "userCertificate") == 0 
                || strcmp(pAttribute, "attributeSecurityGUID") == 0  )
                {
					//BeaconPrintf(CALLBACK_OUTPUT, "\n%s\n", pAttribute);
                    ppValue = (char **)ldap_get_values_lenA(pLdapConnection, pEntry, pAttribute); //not really a char **
                    isbinary = TRUE;
				} else {
                    ppValue = ldap_get_values(
                                pLdapConnection,  // Session Handle
                                pEntry,           // Current entry
                                pAttribute);      // Current attribute
                }
                if (ppValue == NULL) {
                    error = LdapGetLastError();
                    if (error != LDAP_SUCCESS) {
                        print_ldap_error(error);
                        goto end;
                    }
                } else {
                    printAttribute(pAttribute, ppValue);
                    if(isbinary)
                    {ldap_value_free_len((PBERVAL *)ppValue);}
                    else
                    {ldap_value_free(ppValue);}
                    ppValue = NULL;
                }
                ldap_memfree(pAttribute);
                
            }

            //pAttribute is NULL, there could have been an error
            error = LdapGetLastError();
            if (error != LDAP_SUCCESS) {
                print_ldap_error(error);
                goto end;
            }
            
            if( pBer != NULL )
            {
                ber_free(pBer,0);
                pBer = NULL;
            }
        }
        if(totalResults >= results_count && results_count != 0)
        {
            break;
        }
        ldap_msgfree(pSearchResult); pSearchResult = NULL;
    }while(stat == LDAP_SUCCESS);

    end: 
    BeaconPrintf(CALLBACK_OUTPUT, "\nretrieved %lu results total\n", totalResults);
    if(pPageHandle)
    {
        ldap_search_abandon_page(pLdapConnection, pPageHandle);
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
    if(pSearchResult)
    {
        ldap_msgfree(pSearchResult);
        pSearchResult = NULL;
    }
    if (pAttribute)
    {
        ldap_memfree(pAttribute);
    }
    if (ppValue)
    {
        if(isbinary)
        {ldap_value_free_len((PBERVAL *)ppValue);}
        else
        {ldap_value_free(ppValue);}
        ppValue = NULL;
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

	ldapSearch(ldap_filter, ldap_attributes, results_count, scope_of_search, hostname, domain, ldaps==1);

    BeaconPrintf(CALLBACK_OUTPUT, "Started");
}

//A helper macro that will declare main inside the .discard section
//and invoke BeaconInvokeStandalone with the expected packed argument format  
BEACON_MAIN("zziizzi", go)
