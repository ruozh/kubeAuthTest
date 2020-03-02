#include <stdio.h>
#include <string.h>
#include <gssapi/gssapi.h>

const gss_OID_desc krb5 = {10, "\052\206\110\206\367\022\001\002\002\001"};
const gss_OID_desc  * const GSS_KRB5 = &krb5;

int main() {
    // Get token from file.
    gss_buffer_desc input;
//    char com[100000];
//    FILE *f = fopen("/home/msk8s.nttest.microsoft.com/ruozh-user/token.txt", "rb");
//    while (fscanf(f, "%s", com) == 1)
//    {
//        printf("%s", com);
//    }
//    int len = strlen(com);
//    input.length = (size_t) len;
//    const void *v = com;
//    input.value = v;
//    char *x = (char*) input.value;
//    printf("%i", input.length);
//    printf("%s", x);
//    printf("Successfully inject token.");
//
//    fclose(f);

    OM_uint32 maj_stat, min_stat_name, min_stat_cred, min_stat_acc;
    gss_cred_id_t  cred_handle;

    // Initialize the name
    gss_name_t name;
    gss_OID name_type = (gss_OID) GSS_KRB5;

    char n[] = "ruozhservice/ruozhlinad.msk8s.nttest.microsoft.com";
    int l = sizeof(n);
    gss_buffer_desc buf = {l, n};
    maj_stat = gss_import_name(&min_stat_name, &buf, name_type, &name);
    printf("Import name result: ");
    printf("%x\n", maj_stat);

    // Get credential
    // TODO: This doesn't work currently, it always return NO_CRED. We'd probably need to properly setup kerberos
    maj_stat = gss_acquire_cred(&min_stat_cred, name, GSS_C_INDEFINITE,
                                GSS_C_NO_OID_SET, GSS_C_ACCEPT, &cred_handle, NULL, NULL);
    printf("Acquire credential result: ");
    printf("%x\n", maj_stat);

    // Accept context
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_buffer_desc output;
    maj_stat = gss_accept_sec_context(&min_stat_acc, &context, GSS_C_NO_CREDENTIAL, &input, GSS_C_NO_CHANNEL_BINDINGS,
            NULL, NULL, &output, NULL, NULL, NULL);
    if (GSS_ERROR(maj_stat)) {
        printf("Result: ");
        printf("%x\n", maj_stat);
        return 1;
    }
    return 0;
}
