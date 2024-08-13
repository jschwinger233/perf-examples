struct PyTypeObject {
    char _[24];
    char *tp_name;
};
struct PyObject {
    char _[8];
    struct PyTypeObject *ob_type;
};
struct PyVarObject {
    struct PyObject ob_base;
    char _[8];
};

struct _PyStr {
    char _[48];
    char buf[48];
};
struct PyCodeObject {
    char _[104];
    struct _PyStr *co_filename;
    struct _PyStr *co_name;
};

struct PyFrameObject {
    struct PyVarObject ob_base;
    struct PyFrameObject *f_back;
    struct PyCodeObject *f_code;
    char _[60];
    int f_lineno;
};
