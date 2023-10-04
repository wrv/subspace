#ifndef md4c_types_h_
#define md4c_types_h_

#pragma warning(push)
#pragma warning(disable : 4244)
#include "third_party/md4c/src/md4c-html.h"
#include "third_party/md4c/src/md4c.h"
#pragma warning(pop)

#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#elif defined(__GNUC__) || defined(__GNUG__)
// Can't turn off the variadic macro warning emitted from -pedantic
#  pragma GCC system_header
#elif defined(_MSC_VER)
// Doesn't seem to emit the warning
#else
// Don't know the compiler... just let it go through
#endif

// Create aliases to func pointer types
typedef void  (*md4c_process_output)(const MD_CHAR*, MD_SIZE, void*);
typedef int (*md4c_render_self_link)(const MD_CHAR* /*chars*/, MD_SIZE /*size*/, void* /*userdata*/, MD_HTML* /*html*/);
typedef int (*md4c_record_self_link)(const MD_CHAR* /*chars*/, MD_SIZE /*size*/, void* /*userdata*/);
typedef int (*md4c_render_code_link)(const MD_CHAR* /*chars*/, MD_SIZE /*size*/, void* /*userdata*/, MD_HTML* /*html*/);

#define sandbox_fields_reflection_md4c_class_MD_HTML_CALLBACKS_tag(f, g, ...)        \
    f(md4c_process_output   , process_output  , FIELD_NORMAL, ##__VA_ARGS__)    g()   \
    f(md4c_render_self_link , render_self_link, FIELD_NORMAL, ##__VA_ARGS__)    g()   \
    f(md4c_record_self_link , record_self_link, FIELD_NORMAL, ##__VA_ARGS__)    g()   \
    f(md4c_render_code_link , render_code_link, FIELD_NORMAL, ##__VA_ARGS__)    g()

#define sandbox_fields_reflection_md4c_allClasses(f, ...) \
    f(MD_HTML_CALLBACKS_tag, md4c, ##__VA_ARGS__)

#if defined(__clang__)
#  pragma clang diagnostic pop
#elif defined(__GNUC__) || defined(__GNUG__)
#elif defined(_MSC_VER)
#else
#endif


#endif