#include <windows.h>
#include "bofdefs.h"
#include "base.c"

typedef struct {
	char cn[256];
	char sam[256];
	char type[64];
	char whenDeleted[64];
	char dn[512];
	char lastKnownParent[512];
} DELETED_OBJECT;

BOOL GetRootDN(LDAP* ld, char** rootDN) {
	LDAPMessage* res = NULL;
	char* attrs[] = { "rootDomainNamingContext", NULL };

	if (WLDAP32$ldap_search_s(ld, NULL, LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &res) != LDAP_SUCCESS) {
		internal_printf("[-] Failed to get root DN\n");
		return FALSE;
	}

	LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, res);
	if (!entry) {
		internal_printf("[-] No root DN entry found\n");
		WLDAP32$ldap_msgfree(res);
		return FALSE;
	}

	PCHAR* values = WLDAP32$ldap_get_values(ld, entry, "rootDomainNamingContext");
	if (!values || !values[0]) {
		internal_printf("[-] Failed to extract rootDomainNamingContext\n");
		WLDAP32$ldap_msgfree(res);
		return FALSE;
	}

	int len = MSVCRT$strlen(values[0]) + 1;
	*rootDN = (char*)intAlloc(len);
	MSVCRT$strcpy(*rootDN, values[0]);

	WLDAP32$ldap_value_free(values);
	WLDAP32$ldap_msgfree(res);
	return TRUE;
}

// Parse deleted DN to extract CN and deletion GUID
// Format: CN=name\0ADEL:guid,CN=Deleted Objects,...
void ParseDeletedDN(char* dn, char* cn_out, int cn_len) {
	MSVCRT$memset(cn_out, 0, cn_len);

	char* first_comma = MSVCRT$strchr(dn, ',');
	if (!first_comma) {
		MSVCRT$strcpy(cn_out, dn);
		return;
	}

	int cn_part_len = first_comma - dn;
	if (cn_part_len >= cn_len) cn_part_len = cn_len - 1;

	// Copy CN part
	MSVCRT$memcpy(cn_out, dn, cn_part_len);
	cn_out[cn_part_len] = '\0';

	// Remove "CN=" prefix
	if (MSVCRT$strncmp(cn_out, "CN=", 3) == 0) {
		char temp[256] = {0};
		MSVCRT$strcpy(temp, cn_out + 3);
		MSVCRT$strcpy(cn_out, temp);
	}

	// Handle deleted marker - truncate at backslash or ADEL marker
	char* backslash = MSVCRT$strchr(cn_out, '\\');
	if (backslash) {
		*backslash = '\0';
	} else {
		char* adel_marker = MSVCRT$strstr(cn_out, "ADEL:");
		if (adel_marker && adel_marker > cn_out) {
			*(adel_marker - 1) = '\0';
		}
	}
}

// Get object type from objectClass attribute
void ExtractObjectType(LDAP* ld, LDAPMessage* entry, char* type_out, int type_len) {
	PCHAR* values = WLDAP32$ldap_get_values(ld, entry, "objectClass");
	MSVCRT$strcpy(type_out, "unknown");

	if (values) {
		// Check for specific types (check in reverse order of specificity)
		for (int i = 0; values[i] != NULL; i++) {
			if (MSVCRT$strcmp(values[i], "computer") == 0) {
				MSVCRT$strcpy(type_out, "computer");
				break;
			}
			if (MSVCRT$strcmp(values[i], "user") == 0) {
				MSVCRT$strcpy(type_out, "user");
			}
			if (MSVCRT$strcmp(values[i], "group") == 0) {
				MSVCRT$strcpy(type_out, "group");
				break;
			}
		}
		WLDAP32$ldap_value_free(values);
	}
}

// Get string value from entry
void GetStringValue(LDAP* ld, LDAPMessage* entry, const char* attr, char* value_out, int value_len) {
	MSVCRT$memset(value_out, 0, value_len);
	PCHAR* values = WLDAP32$ldap_get_values(ld, entry, (PSTR)attr);
	if (values && values[0]) {
		int len = MSVCRT$strlen(values[0]);
		if (len >= value_len) len = value_len - 1;
		MSVCRT$memcpy(value_out, values[0], len);
		value_out[len] = '\0';
		WLDAP32$ldap_value_free(values);
	}
}

ULONG ListDeletedObjects(LDAP* ld, char* rootDN) {
	LDAPMessage* res = NULL;
	char searchDN[512] = {0};
	char* attrs[] = {
		"sAMAccountName", "objectClass", "whenDeleted", "lastKnownParent",
		"userAccountControl", "adminCount", "description", NULL
	};
	ULONG ldapErr = 0;
	LDAP_TIMEVAL timeout = {0};
	LDAPControlA showDeletedControl = {0};
	PLDAPControlA controls[] = { &showDeletedControl, NULL };
	ULONG entryCount = 0;

	MSVCRT$sprintf(searchDN, "CN=Deleted Objects,%s", rootDN);
	internal_printf("\n[*] Searching deleted objects in: %s\n\n", searchDN);

	// Setup SHOW_DELETED control
	showDeletedControl.ldctl_oid = (PCHAR)LDAP_CONTROL_SHOW_DELETED_OID_STRING;
	showDeletedControl.ldctl_iscritical = FALSE;
	showDeletedControl.ldctl_value.bv_len = 0;
	showDeletedControl.ldctl_value.bv_val = NULL;

	// Set timeout to 10 seconds
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	// Search for deleted objects
	ldapErr = WLDAP32$ldap_search_ext_s(
		ld,
		searchDN,
		LDAP_SCOPE_ONELEVEL,
		"(isDeleted=TRUE)",
		attrs,
		0,
		controls,
		NULL,
		&timeout,
		1000,
		&res
	);

	if (ldapErr != LDAP_SUCCESS) {
		internal_printf("[-] Search failed (LDAP error: %lu)\n", ldapErr);
		return 0;
	}

	if (!res) {
		internal_printf("[*] No results returned\n");
		return 0;
	}

	entryCount = WLDAP32$ldap_count_entries(ld, res);
	internal_printf("[+] Found %lu deleted object(s)\n\n", entryCount);
	internal_printf("%-30s | %-20s | %-15s | %s\n", "Name", "SAMAccountName", "Type", "Deleted");
	internal_printf("%.*s\n", 100, "====================================================================================================");

	LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, res);
	ULONG displayed = 0;

	while (entry) {
		char cn[256] = {0};
		char sam[256] = {0};
		char type[64] = {0};
		char whenDeleted[64] = {0};
		char* dn = NULL;

		dn = WLDAP32$ldap_get_dn(ld, entry);
		if (dn) {
			ParseDeletedDN(dn, cn, sizeof(cn));
			WLDAP32$ldap_memfree(dn);
		}

		GetStringValue(ld, entry, "sAMAccountName", sam, sizeof(sam));
		ExtractObjectType(ld, entry, type, sizeof(type));
		GetStringValue(ld, entry, "whenDeleted", whenDeleted, sizeof(whenDeleted));

		// Truncate long strings for display
		if (MSVCRT$strlen(cn) > 30) cn[27] = cn[28] = cn[29] = '.';
		if (MSVCRT$strlen(sam) > 20) sam[17] = sam[18] = sam[19] = '.';

		internal_printf("%-30s | %-20s | %-15s | %s\n", cn, sam, type, whenDeleted);

		displayed++;
		entry = WLDAP32$ldap_next_entry(ld, entry);
	}

	internal_printf("%.*s\n", 100, "====================================================================================================");
	internal_printf("\n[+] Displayed %lu objects\n\n", displayed);

	WLDAP32$ldap_msgfree(res);
	return displayed;
}

#ifdef BOF
VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	if (!bofstart()) {
		return;
	}

	LDAP* ld = NULL;
	char* rootDN = NULL;

	internal_printf("[*] Enumerating Active Directory Recycling Bin objects...\n");

	ld = WLDAP32$ldap_init(NULL, LDAP_PORT);
	if (!ld) {
		internal_printf("[-] Failed to initialize LDAP\n");
		goto cleanup;
	}

	internal_printf("[+] LDAP initialized\n");

	if (WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
		internal_printf("[-] Failed to bind to LDAP\n");
		goto cleanup;
	}

	internal_printf("[+] LDAP bound successfully\n");

	if (!GetRootDN(ld, &rootDN)) {
		internal_printf("[-] Failed to get root DN\n");
		goto cleanup;
	}

	internal_printf("[+] Root DN: %s\n", rootDN);

	ListDeletedObjects(ld, rootDN);

cleanup:
	if (rootDN) {
		intFree(rootDN);
	}
	if (ld) {
		WLDAP32$ldap_unbind(ld);
	}

	printoutput(TRUE);
};

#else

int main() {
	LDAP* ld = NULL;
	char* rootDN = NULL;

	printf("[*] Enumerating Active Directory Recycling Bin objects...\n");

	ld = WLDAP32$ldap_init(NULL, LDAP_PORT);
	if (!ld) {
		printf("[-] Failed to initialize LDAP\n");
		return 1;
	}

	printf("[+] LDAP initialized\n");

	if (WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
		printf("[-] Failed to bind to LDAP\n");
		WLDAP32$ldap_unbind(ld);
		return 1;
	}

	printf("[+] LDAP bound successfully\n");

	if (GetRootDN(ld, &rootDN)) {
		printf("[+] Root DN: %s\n", rootDN);
		ListDeletedObjects(ld, rootDN);
		free(rootDN);
	}

	WLDAP32$ldap_unbind(ld);
	return 0;
}

#endif
