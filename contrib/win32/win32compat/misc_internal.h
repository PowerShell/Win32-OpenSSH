
/* removes first '/' for Windows paths that are unix styled. Ex: /c:/ab.cd */
#define sanitized_path(p) (((p)[0] == '/' && (p)[1] != '\0' && (p)[2] == ':')? (p)+1 : (p))