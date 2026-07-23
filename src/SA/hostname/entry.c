#include <windows.h>
#include "bofdefs.h"
#include "base.c"

// Constants
#define NERR_Success 0
#define NetSetupUnknownStatus 0
#define NetSetupUnjoined 1
#define NetSetupWorkgroupName 2
#define NetSetupDomainName 3

#ifdef BOF

VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	if(!bofstart())
	{
		return;
	}

	WCHAR wcHostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
	DWORD dwHostnameSize = MAX_COMPUTERNAME_LENGTH + 1;
	LPWSTR lpNetbiosDomain = NULL;
	DWORD joinStatus = NetSetupUnknownStatus;
	DWORD dwRet = 0;
	LDAP* pLdapConnection = NULL;
	LDAPMessage* pSearchResult = NULL;
	LDAPMessage* pEntry = NULL;
	PCHAR* ppszValues = NULL;
	WCHAR wcDomainDN[512] = {0};
	WCHAR wcDomain[256] = {0};
	int i = 0;

	// Get NetBIOS hostname using GetComputerNameExW with ComputerNameNetBIOS (0)
	if (!KERNEL32$GetComputerNameExW(0, wcHostname, &dwHostnameSize)) {
		BeaconPrintf(CALLBACK_ERROR, "GetComputerNameExW failed: %d", KERNEL32$GetLastError());
		goto cleanup;
	}

	BeaconPrintf(CALLBACK_OUTPUT, "[*] Computer Name: %ls", wcHostname);

	// Use NetGetJoinInformation to detect domain status
	dwRet = NETAPI32$NetGetJoinInformation(NULL, &lpNetbiosDomain, (DWORD*)&joinStatus);

	if (dwRet == NERR_Success) {
		if (joinStatus == NetSetupDomainName) {
			// Domain joined - use LDAP to query rootDSE for domain name
			pLdapConnection = WLDAP32$ldap_initW(NULL, LDAP_PORT);

			if (pLdapConnection != NULL) {
				// Bind to LDAP with default credentials
				dwRet = WLDAP32$ldap_bind_s(pLdapConnection, NULL, NULL, LDAP_AUTH_SIMPLE);

				if (dwRet == LDAP_SUCCESS) {
					// Query rootDSE for defaultNamingContext
					PCHAR ppszAttrs[] = { "defaultNamingContext", NULL };
					dwRet = WLDAP32$ldap_search_s(pLdapConnection, "", LDAP_SCOPE_BASE, "(objectClass=*)", ppszAttrs, 0, &pSearchResult);

					if (dwRet == LDAP_SUCCESS && pSearchResult != NULL) {
						pEntry = WLDAP32$ldap_first_entry(pLdapConnection, pSearchResult);

						if (pEntry != NULL) {
							ppszValues = WLDAP32$ldap_get_values(pLdapConnection, pEntry, "defaultNamingContext");

							if (ppszValues != NULL && ppszValues[0] != NULL) {
								// Convert DN to domain name (DC=yyy,DC=zzz -> yyy.zzz)
								PCHAR pDN = ppszValues[0];
								PCHAR pDCPart = MSVCRT$strstr(pDN, "DC=");

								if (pDCPart != NULL) {
									// Parse DC components starting from first DC=
									int domainLen = 0;
									PCHAR pTemp = pDCPart;

									while (pTemp != NULL && *pTemp != '\0') {
										if (*pTemp == 'D' && *(pTemp + 1) == 'C' && *(pTemp + 2) == '=') {
											// Found DC= marker
											pTemp += 3;
											int len = 0;
											// Get length of this component (until comma, space, or end)
											while (pTemp[len] != '\0' && pTemp[len] != ',' && pTemp[len] != ' ') {
												len++;
											}
											if (len > 0) {
												// Add dot separator if not first component
												if (domainLen > 0 && domainLen < 250) {
													wcDomain[domainLen++] = L'.';
												}
												// Copy ASCII to wide char
												for (int j = 0; j < len && domainLen < 250; j++) {
													wcDomain[domainLen++] = (WCHAR)pTemp[j];
												}
											}
											pTemp += len;
										} else {
											pTemp++;
										}
									}

									if (domainLen > 0) {
										wcDomain[domainLen] = L'\0';
										BeaconPrintf(CALLBACK_OUTPUT, "[+] FQDN: %ls.%ls", wcHostname, wcDomain);
										BeaconPrintf(CALLBACK_OUTPUT, "[+] Domain: %ls", wcDomain);
									}
								}

								WLDAP32$ldap_value_free(ppszValues);
							}
						}

						if (pSearchResult != NULL) {
							WLDAP32$ldap_msgfree(pSearchResult);
						}
					}
				}

				if (pLdapConnection != NULL) {
					WLDAP32$ldap_unbind(pLdapConnection);
				}
			} else {
				BeaconPrintf(CALLBACK_ERROR, "Failed to connect to LDAP");
			}
		} else if (joinStatus == NetSetupWorkgroupName) {
			// Workgroup member
			BeaconPrintf(CALLBACK_OUTPUT, "[-] Not domain joined (workgroup member)");
			if (lpNetbiosDomain && MSVCRT$wcslen(lpNetbiosDomain) > 0) {
				BeaconPrintf(CALLBACK_OUTPUT, "[*] Workgroup: %ls", lpNetbiosDomain);
			}
		} else {
			// Unknown status
			BeaconPrintf(CALLBACK_OUTPUT, "[-] Unknown join status: %d", joinStatus);
		}

		if (lpNetbiosDomain) {
			NETAPI32$NetApiBufferFree(lpNetbiosDomain);
		}
	} else {
		BeaconPrintf(CALLBACK_ERROR, "NetGetJoinInformation failed: 0x%08X", dwRet);
	}

cleanup:
	printoutput(TRUE);
}

#else

#include <stdio.h>
#include <string.h>

#define NERR_Success 0
#define NetSetupUnknownStatus 0
#define NetSetupUnjoined 1
#define NetSetupWorkgroupName 2
#define NetSetupDomainName 3

int main()
{
	// Standalone version for testing/leak checks
	WCHAR wcHostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
	DWORD dwHostnameSize = MAX_COMPUTERNAME_LENGTH + 1;
	LPWSTR lpNetbiosDomain = NULL;
	DWORD joinStatus = NetSetupUnknownStatus;
	DWORD dwRet = 0;
	LDAP* pLdapConnection = NULL;
	LDAPMessage* pSearchResult = NULL;
	LDAPMessage* pEntry = NULL;
	PCHAR* ppszValues = NULL;
	WCHAR wcDomain[256] = {0};

	// Get hostname
	if (GetComputerNameExW(0, wcHostname, &dwHostnameSize)) {
		wprintf(L"[*] Computer Name: %ls\n", wcHostname);

		// Use NetGetJoinInformation to detect domain status
		dwRet = NetGetJoinInformation(NULL, &lpNetbiosDomain, &joinStatus);

		if (dwRet == NERR_Success) {
			if (joinStatus == NetSetupDomainName) {
				// Domain joined - use LDAP to query rootDSE for domain name
				pLdapConnection = ldap_initW(NULL, LDAP_PORT);

				if (pLdapConnection != NULL) {
					dwRet = ldap_bind_s(pLdapConnection, NULL, NULL, LDAP_AUTH_SIMPLE);

					if (dwRet == LDAP_SUCCESS) {
						PCHAR ppszAttrs[] = { "defaultNamingContext", NULL };
						dwRet = ldap_search_s(pLdapConnection, "", LDAP_SCOPE_BASE, "(objectClass=*)", ppszAttrs, 0, &pSearchResult);

						if (dwRet == LDAP_SUCCESS && pSearchResult != NULL) {
							pEntry = ldap_first_entry(pLdapConnection, pSearchResult);

							if (pEntry != NULL) {
								ppszValues = ldap_get_values(pLdapConnection, pEntry, "defaultNamingContext");

								if (ppszValues != NULL && ppszValues[0] != NULL) {
									// Parse DN to get domain
									PCHAR pDN = ppszValues[0];
									PCHAR pDCPart = strstr(pDN, "DC=");

									if (pDCPart != NULL) {
										// Parse DC components starting from first DC=
										int domainLen = 0;
										PCHAR pTemp = pDCPart;

										while (pTemp != NULL && *pTemp != '\0') {
											if (*pTemp == 'D' && *(pTemp + 1) == 'C' && *(pTemp + 2) == '=') {
												// Found DC= marker
												pTemp += 3;
												int len = 0;
												// Get length of this component
												while (pTemp[len] != '\0' && pTemp[len] != ',' && pTemp[len] != ' ') {
													len++;
												}
												if (len > 0) {
													// Add dot separator if not first component
													if (domainLen > 0 && domainLen < 250) {
														wcDomain[domainLen++] = L'.';
													}
													// Copy ASCII to wide char
													for (int j = 0; j < len && domainLen < 250; j++) {
														wcDomain[domainLen++] = (WCHAR)pTemp[j];
													}
												}
												pTemp += len;
											} else {
												pTemp++;
											}
										}

										if (domainLen > 0) {
											wcDomain[domainLen] = L'\0';
											wprintf(L"[+] FQDN: %ls.%ls\n", wcHostname, wcDomain);
											//wprintf(L"[+] Domain: %ls\n", wcDomain);
										}
									}

									ldap_value_free(ppszValues);
								}
							}

							if (pSearchResult != NULL) {
								ldap_msgfree(pSearchResult);
							}
						}
					}

					if (pLdapConnection != NULL) {
						ldap_unbind(pLdapConnection);
					}
				} else {
					printf("[-] Failed to connect to LDAP\n");
				}
			} else if (joinStatus == NetSetupWorkgroupName) {
				wprintf(L"[-] Not domain joined (workgroup member)\n");
				if (lpNetbiosDomain) {
					wprintf(L"[*] Workgroup: %ls\n", lpNetbiosDomain);
				}
			}

			if (lpNetbiosDomain) {
				NetApiBufferFree(lpNetbiosDomain);
			}
		} else {
			printf("[-] NetGetJoinInformation failed: 0x%08X\n", dwRet);
		}
	} else {
		printf("[-] GetComputerNameExW failed\n");
	}

	return 0;
}

#endif