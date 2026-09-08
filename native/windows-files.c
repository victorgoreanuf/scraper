#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <io.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <wchar.h>
#include <node_api.h>
#define USING_UV_SHARED 1
#include <uv.h>

static napi_value fail(napi_env env, const char *operation, DWORD error) {
  const char *code = "EIO";
  switch (error) {
    case ERROR_FILE_NOT_FOUND: case ERROR_PATH_NOT_FOUND: code = "ENOENT"; break;
    case ERROR_ALREADY_EXISTS: case ERROR_FILE_EXISTS: code = "EEXIST"; break;
    case ERROR_ACCESS_DENIED: case ERROR_SHARING_VIOLATION: code = "EACCES"; break;
    case ERROR_CANT_ACCESS_FILE: code = "ELOOP"; break;
    case ERROR_NOT_SUPPORTED: code = "ENOTSUP"; break;
    case ERROR_INVALID_PARAMETER: case ERROR_INVALID_NAME: code = "EINVAL"; break;
  }
  napi_value message, value, label, number;
  napi_create_string_utf8(env, operation, NAPI_AUTO_LENGTH, &message);
  napi_create_error(env, NULL, message, &value);
  napi_create_string_utf8(env, code, NAPI_AUTO_LENGTH, &label);
  napi_set_named_property(env, value, "code", label);
  napi_create_uint32(env, error, &number);
  napi_set_named_property(env, value, "win32Error", number);
  napi_throw(env, value);
  return NULL;
}

static TOKEN_USER *current_user(void) {
  HANDLE token = NULL;
  DWORD size = 0;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return NULL;
  GetTokenInformation(token, TokenUser, NULL, 0, &size);
  TOKEN_USER *user = (TOKEN_USER *)malloc(size);
  if (!user) { CloseHandle(token); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
  if (!GetTokenInformation(token, TokenUser, user, size, &size)) {
    DWORD error = GetLastError(); free(user); CloseHandle(token); SetLastError(error); return NULL;
  }
  CloseHandle(token);
  return user;
}

static PSECURITY_DESCRIPTOR private_descriptor(void) {
  TOKEN_USER *user = current_user();
  if (!user) return NULL;
  LPWSTR sid = NULL;
  if (!ConvertSidToStringSidW(user->User.Sid, &sid)) { free(user); return NULL; }
  wchar_t sddl[512];
  swprintf_s(sddl, 512, L"O:%lsD:P(A;;FA;;;%ls)(A;;FA;;;SY)(A;;FA;;;BA)", sid, sid);
  LocalFree(sid); free(user);
  PSECURITY_DESCRIPTOR descriptor = NULL;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, NULL)) return NULL;
  return descriptor;
}

static HANDLE argument_handle(napi_env env, napi_value value) {
  int32_t fd;
  if (napi_get_value_int32(env, value, &fd) != napi_ok || fd < 0) return INVALID_HANDLE_VALUE;
  return (HANDLE)uv_get_osfhandle(fd);
}

static napi_value open_file(napi_env env, napi_callback_info info) {
  napi_value args[3]; size_t argc = 3; int32_t flags; bool private_create;
  napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  if (argc != 3 || napi_get_value_int32(env, args[1], &flags) != napi_ok || napi_get_value_bool(env, args[2], &private_create) != napi_ok)
    return fail(env, "Invalid file open arguments.", ERROR_INVALID_PARAMETER);
  size_t size = 0;
  if (napi_get_value_string_utf16(env, args[0], NULL, 0, &size) != napi_ok || size < 3 || size > 32760)
    return fail(env, "Invalid local file path.", ERROR_INVALID_NAME);
  wchar_t *path = (wchar_t *)calloc(size + 5, sizeof(wchar_t));
  if (!path) return fail(env, "File path allocation failed.", ERROR_NOT_ENOUGH_MEMORY);
  wcscpy_s(path, size + 5, L"\\\\?\\");
  napi_get_value_string_utf16(env, args[0], (char16_t *)(path + 4), size + 1, &size);
  if (wcslen(path + 4) != size || path[5] != L':' || path[6] != L'\\' || wcschr(path + 6, L':') != NULL) {
    free(path); return fail(env, "Only absolute local drive paths without alternate streams are supported.", ERROR_NOT_SUPPORTED);
  }
  wchar_t root[4] = {path[4], L':', L'\\', 0};
  if (GetDriveTypeW(root) != DRIVE_FIXED) { free(path); return fail(env, "A fixed local output/input volume is required.", ERROR_NOT_SUPPORTED); }
  /* Never accept truncating or nonexclusive creating flags before identity validation. */
  int allowed = _O_RDONLY | _O_WRONLY | _O_RDWR | _O_CREAT | _O_EXCL;
  if ((flags & (_O_WRONLY | _O_RDWR)) == (_O_WRONLY | _O_RDWR) || (flags & ~allowed) != 0 || ((flags & _O_CREAT) && !(flags & _O_EXCL)) || ((flags & _O_EXCL) && !(flags & _O_CREAT))) {
    free(path); return fail(env, "Unsupported safe file open flags.", ERROR_INVALID_PARAMETER);
  }
  DWORD access = (flags & _O_RDWR) ? (GENERIC_READ | GENERIC_WRITE | WRITE_DAC) :
    ((flags & _O_WRONLY) ? (GENERIC_WRITE | READ_CONTROL | WRITE_DAC) : (GENERIC_READ | READ_CONTROL));
  PSECURITY_DESCRIPTOR descriptor = private_create ? private_descriptor() : NULL;
  if (private_create && !descriptor) { DWORD error = GetLastError(); free(path); return fail(env, "Private file descriptor could not be created.", error); }
  SECURITY_ATTRIBUTES attributes = {sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
  HANDLE handle = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    descriptor ? &attributes : NULL, (flags & _O_CREAT) ? CREATE_NEW : OPEN_EXISTING,
    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
  DWORD error = GetLastError();
  free(path); if (descriptor) LocalFree(descriptor);
  if (handle == INVALID_HANDLE_VALUE) return fail(env, "Safe file open failed.", error);
  BY_HANDLE_FILE_INFORMATION details;
  if (GetFileType(handle) != FILE_TYPE_DISK || !GetFileInformationByHandle(handle, &details)) {
    error = GetLastError(); CloseHandle(handle); return fail(env, "File is not a regular disk file.", error ? error : ERROR_NOT_SUPPORTED);
  }
  if (details.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) {
    CloseHandle(handle); return fail(env, "Reparse points and directories are not regular file targets.", ERROR_CANT_ACCESS_FILE);
  }
  int fd = uv_open_osfhandle(handle);
  if (fd < 0) { CloseHandle(handle); return fail(env, "File descriptor adoption failed.", ERROR_TOO_MANY_OPEN_FILES); }
  napi_value result; napi_create_int32(env, fd, &result); return result;
}

static napi_value protect_file(napi_env env, napi_callback_info info) {
  napi_value arg; size_t argc = 1; napi_get_cb_info(env, info, &argc, &arg, NULL, NULL);
  HANDLE handle = argc == 1 ? argument_handle(env, arg) : INVALID_HANDLE_VALUE;
  if (handle == INVALID_HANDLE_VALUE) return fail(env, "Invalid file descriptor.", ERROR_INVALID_PARAMETER);
  PSID owner = NULL; PSECURITY_DESCRIPTOR existing = NULL;
  DWORD error = GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
    &owner, NULL, NULL, NULL, &existing);
  if (error != ERROR_SUCCESS) return fail(env, "File owner could not be inspected.", error);
  TOKEN_USER *user = current_user();
  if (!user) {
    error = GetLastError(); LocalFree(existing);
    return fail(env, "Current user could not be inspected.", error);
  }
  BOOL owned = owner != NULL && EqualSid(owner, user->User.Sid);
  free(user); LocalFree(existing);
  if (!owned) return fail(env, "Private output must be owned by the current user.", ERROR_ACCESS_DENIED);
  PSECURITY_DESCRIPTOR descriptor = private_descriptor();
  if (!descriptor) return fail(env, "Private ACL could not be prepared.", GetLastError());
  PACL acl = NULL; BOOL present, defaulted;
  if (!GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) || !present || acl == NULL) {
    LocalFree(descriptor); return fail(env, "Private ACL is invalid.", ERROR_INVALID_SECURITY_DESCR);
  }
  error = SetSecurityInfo(handle, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
    NULL, NULL, acl, NULL);
  LocalFree(descriptor);
  if (error != ERROR_SUCCESS) return fail(env, "Private ACL could not be applied to the validated descriptor.", error);
  napi_value result; napi_get_undefined(env, &result); return result;
}
static napi_value is_private(napi_env env, napi_callback_info info) {
  napi_value arg; size_t argc = 1; napi_get_cb_info(env, info, &argc, &arg, NULL, NULL);
  HANDLE handle = argc == 1 ? argument_handle(env, arg) : INVALID_HANDLE_VALUE;
  if (handle == INVALID_HANDLE_VALUE) return fail(env, "Invalid file descriptor.", ERROR_INVALID_PARAMETER);
  PACL acl = NULL; PSID owner = NULL; PSECURITY_DESCRIPTOR descriptor = NULL;
  DWORD error = GetSecurityInfo(handle, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
    &owner, NULL, &acl, NULL, &descriptor);
  if (error != ERROR_SUCCESS) return fail(env, "File ACL could not be inspected.", error);
  TOKEN_USER *user = current_user();
  if (!user) { LocalFree(descriptor); return fail(env, "Current user could not be inspected.", GetLastError()); }
  BYTE system_sid[SECURITY_MAX_SID_SIZE], admin_sid[SECURITY_MAX_SID_SIZE];
  DWORD system_size = sizeof(system_sid), admin_size = sizeof(admin_sid);
  CreateWellKnownSid(WinLocalSystemSid, NULL, system_sid, &system_size);
  CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admin_sid, &admin_size);
  SECURITY_DESCRIPTOR_CONTROL control; DWORD revision;
  GetSecurityDescriptorControl(descriptor, &control, &revision);
  BOOL valid = owner != NULL && EqualSid(owner, user->User.Sid)
    && acl != NULL && (control & SE_DACL_PROTECTED) != 0;
  BOOL user_full = FALSE;
  for (DWORD i = 0; valid && i < acl->AceCount; ++i) {
    ACE_HEADER *header = NULL;
    if (!GetAce(acl, i, (void **)&header)) { valid = FALSE; break; }
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceFlags != 0) { valid = FALSE; break; }
    ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)header;
    PSID sid = (PSID)&ace->SidStart;
    BOOL own = EqualSid(sid, user->User.Sid);
    if (!own && !EqualSid(sid, system_sid) && !EqualSid(sid, admin_sid)) { valid = FALSE; break; }
    if (own && (ace->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS) user_full = TRUE;
  }
  free(user); LocalFree(descriptor);
  napi_value result; napi_get_boolean(env, valid && user_full, &result); return result;
}

static napi_value init(napi_env env, napi_value exports) {
  napi_property_descriptor properties[] = {
    {"open", NULL, open_file, NULL, NULL, NULL, napi_default, NULL},
    {"protect", NULL, protect_file, NULL, NULL, NULL, napi_default, NULL},
    {"isPrivate", NULL, is_private, NULL, NULL, NULL, napi_default, NULL}
  };
  napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties);
  return exports;
}
NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
