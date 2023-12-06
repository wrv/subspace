// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "subdoc/lib/gen/markdown_to_html.h"

#include <sstream>

#include "fmt/format.h"
#include "subdoc/lib/gen/files.h"
#include "sus/ops/range.h"

// Comment out to use the NOOP sandbox
#define USE_WASM_SBX

// Use RLBox in a single-threaded environment
#define RLBOX_SINGLE_THREADED_INVOCATIONS

#ifdef USE_WASM_SBX

// All calls into the sandbox are resolved statically.
#define RLBOX_USE_STATIC_CALLS() rlbox_wasm2c_sandbox_lookup_symbol
#define RLBOX_WASM2C_MODULE_NAME  md4c

#include "third_party/md4c/src/md4c.wasm.h"
#include "third_party/rlbox/code/include/rlbox.hpp"
#include "third_party/rlbox_wasm2c_sandbox/include/rlbox_wasm2c_sandbox.hpp"

using namespace rlbox;

// Define base type for md4c using the wasm2c sandbox
RLBOX_DEFINE_BASE_TYPES_FOR(md4c, wasm2c)

#else

// All calls into the sandbox are resolved statically.
#define RLBOX_USE_STATIC_CALLS() rlbox_noop_sandbox_lookup_symbol

#include "third_party/rlbox/code/include/rlbox.hpp"
#include "third_party/rlbox/code/include/rlbox_noop_sandbox.hpp"

using namespace rlbox;

// Define base type for md4c using the wasm2c sandbox
RLBOX_DEFINE_BASE_TYPES_FOR(md4c, noop)
#endif

#include "subdoc/lib/gen/rlbox_md4c_types.h"
rlbox_load_structs_from_library(md4c);

namespace subdoc::gen {

namespace {

struct UserData {
  std::ostringstream& parsed;
  ParseMarkdownPageState& page_state;
  sus::Option<std::string> error_message;
};

// UserData is not modified within md4c, so never send it to
// the library so it has no chance of corrupting it.
thread_local UserData* userdata = nullptr;

/// Grabs the contents of the first non-empty html tag as the summary.
std::string summarize_html(std::string_view html) noexcept {
  if (html.empty()) return std::string(html);

  bool inside_tag = false;
  i32 tag_depth = 0;
  Option<size_t> start_non_empty;
  for (auto i : sus::ops::range<usize>(0u, html.size())) {
    if (inside_tag) {
      if (html[i] == '>') {
        inside_tag = false;
      }
    } else {
      if (html.substr(i).starts_with("<")) {
        inside_tag = true;
        if (start_non_empty.is_some()) {
          if (html.substr(i).starts_with("</")) {
            if (start_non_empty.is_some() && tag_depth == 0) {
              std::ostringstream summary;
              summary << "<p>";
              summary << html.substr(start_non_empty.as_value(),
                                     i - start_non_empty.as_value());
              summary << "</p>";
              return summary.str();
            }

            tag_depth -= 1;
          } else {
            tag_depth += 1;
          }
        }
      } else {
        // We see a character that's not part of an html tag.
        start_non_empty = start_non_empty.or_that(sus::some(i));
      }
    }
  }
  llvm::errs() << "WARNING: Html summary could not find non-empty tag pair.\n";
  llvm::errs() << html << "\n";
  return std::string(html);
}

/// Removes html tags, leaving behind the text content.
std::string drop_tags(std::string_view html) noexcept {
  if (html.empty()) return std::string(html);

  std::ostringstream s;

  bool inside_tag = false;
  Option<usize> text_start;
  for (auto i : sus::ops::range<usize>(0u, html.size())) {
    if (inside_tag) {
      if (html[i] == '>') {
        inside_tag = false;
        text_start.insert(i + 1u);
      }
    } else {
      if (html.substr(i).starts_with("<")) {
        inside_tag = true;
        if (text_start.is_some()) {
          s << html.substr(*text_start, i - *text_start);
          text_start = sus::none();
        }
      }
    }
  }
  std::string without_tags = sus::move(s).str();
  usize pos;
  while (true) {
    pos = without_tags.find('\n', pos);
    if (pos == std::string::npos) break;
    without_tags.replace(pos, 1u, " ");
    pos += 1u;
  }
  return without_tags;
}

void apply_syntax_highlighting(std::string& str) noexcept {
  // Never remove or reorder anything in here =). Add new stuff at the end.
  // clang-format off
  constexpr auto INSERTS = sus::Array<std::string_view, 7u>(
    // </span> is first in the list, so when we sort insertions, span
    // closers will always come before new openers at the same position.
    "</span>",
    "<span class=\"comment\">",
    "<span class=\"string\">",
    "<span class=\"char-escape\">",
    "<span class=\"char\">",
    "<span class=\"keyword\">",
    "<span class=\"punct\">"
  );
  // clang-format on

  // A set of (position, INSERTS index), which indicate the string at index
  // should be inserted at the position in str.
  Vec<sus::Tuple<usize, usize>> inserts;

  usize pos;
  auto view = std::string_view(str);
  while (true) {
    // Find the <pre> tags.
    pos = view.find("<pre>", pos);
    if (pos == std::string::npos) break;
    pos += 5u;
    usize end_pos = view.find("</pre>", pos);
    if (end_pos == std::string::npos) break;

    // Inside <pre>, find the <code> tags and move inside them.
    pos = [&](usize pos) {
      usize plain = view.find("<code>", pos);
      if (plain != std::string::npos) plain += strlen("<code>");
      usize with_lang = view.find("<code class=\"language-cpp\">", pos);
      if (with_lang != std::string::npos)
        with_lang += strlen("<code class=\"language-cpp\">");
      return sus::cmp::min(plain, with_lang);
    }(pos);
    if (pos == std::string::npos) break;
    end_pos = sus::cmp::min(end_pos, usize::from(view.find("</code>", pos)));

    bool in_comment = false;
    bool in_string = false;
    bool in_char = false;
    while (pos < end_pos) {
      // Comments come first, and eat everything inside them.
      if (in_comment) {
        if (view[pos] == '\n') {
          in_comment = false;
          inserts.push(sus::tuple(pos, 0u));  // End comment.
        }
        pos += 1u;
        continue;  // Each everything to end of comment.
      }

      // Char escapes get highlight everywhere except in comments.
      if (view.substr(pos, 7u) == "\\&quot;") {
        inserts.push(sus::tuple(pos, 3u));       // Start char-escape.
        inserts.push(sus::tuple(pos + 7u, 0u));  // End char-escape.
        pos += 7u;
        continue;
      }
      if (view[pos] == '\\' && pos < view.size() - 1u) {
        inserts.push(sus::tuple(pos, 3u));       // Start char-escape.
        inserts.push(sus::tuple(pos + 2u, 0u));  // End char-escape.
        pos += 2u;
        continue;
      }

      // Chars and string blocks each everything inside them.
      if (in_char) {
        if (view[pos] == '\'') {
          in_char = false;
          pos += 1u;
          inserts.push(sus::tuple(pos, 0u));  // End string.
        } else {
          pos += 1u;
        }
        continue;  // Eat everything to the end of char.
      }
      if (in_string) {
        if (view.substr(pos, 6u) == "&quot;") {
          in_string = false;
          pos += 6u;
          inserts.push(sus::tuple(pos, 0u));  // End string.
        } else {
          pos += 1u;
        }
        continue;  // Eat everything to the end of string.
      }

      // The start of comments, strings, or chars.
      if (view.substr(pos, 2u) == "//") {
        in_comment = true;
        inserts.push(sus::tuple(pos, 1u));  // Start comment.
        pos += 2u;
        continue;
      }
      if (view.substr(pos, 6u) == "&quot;") {
        in_string = true;
        inserts.push(sus::tuple(pos, 2u));  // Start string.
        pos += 6u;
        continue;
      }
      if (view[pos] == '\'') {
        in_char = true;
        inserts.push(sus::tuple(pos, 4u));  // Start char.
        pos += 1u;
        continue;
      }

      // There's a <code> tag at the start so we can always look backward one
      // char.
      sus_check(pos > 0u);
      char before = view[pos - 1u];

      // True if `c` is a character that is a valid part of an identifier.
      auto is_id_char = [](char c) {
        return (c >= 'a' && c <= 'z') ||  //
               (c >= 'A' && c <= 'Z') ||  //
               (c >= '0' && c <= '9') ||  //
               c == '_';
      };
      auto is_punct = [](char c) {
        // The `&`, `<` and `>` are escaped so we look elsewhere for them.
        constexpr auto PUNCTS = std::string_view("{}[](),.;!|^*%+-=");
        return PUNCTS.find(c) != std::string_view::npos;
      };

      if (!is_id_char(before)) {
        constexpr auto KEYWORDS = sus::Array<std::string_view, 95u>(
            "alignas", "alignof", "and", "and_eq", "asm", "atomic_cancel",
            "atomic_commit", "atomic_noexcept", "auto", "bitand", "bitor",
            "bool", "break", "case", "catch", "char", "char8_t", "char16_t",
            "char32_t", "class", "compl", "concept", "const", "consteval",
            "constexpr", "constinit", "const_cast", "continue", "co_await",
            "co_return", "co_yield", "decltype", "default", "delete", "do",
            "double", "dynamic_cast", "else", "enum", "explicit", "export",
            "extern", "false", "float", "for", "friend", "goto", "if", "inline",
            "int", "long", "mutable", "namespace", "new", "noexcept", "not",
            "not_eq", "nullptr", "operator", "or", "or_eq", "private",
            "protected", "public", "register", "reinterpret_cast", "requires",
            "return", "short", "signed", "sizeof", "static", "static_assert",
            "static_cast", "struct", "switch", "template", "this",
            "thread_local", "throw", "true", "try", "typedef", "typeid",
            "typename", "union", "unsigned", "using", "virtual", "void",
            "volatile", "wchar_t", "while", "xor", "xor_eq");

        for (std::string_view k : KEYWORDS) {
          usize len = k.size();
          if (auto sub = view.substr(pos, len + 1u);  //
              sub.size() == len + 1u && sub.substr(0u, len) == k &&
              !is_id_char(sub[len])) {
            inserts.push(sus::tuple(pos, 5u));        // Start keyword.
            inserts.push(sus::tuple(pos + len, 0u));  // End keyword.
            pos += len;
            continue;
          }
        }
      }

      if (is_punct(view[pos])) {
        inserts.push(sus::tuple(pos, 6u));       // Start punct.
        inserts.push(sus::tuple(pos + 1u, 0u));  // End punct.
        pos += 1u;
        continue;
      }
      if (view.substr(pos, 5u) == "&amp;") {
        inserts.push(sus::tuple(pos, 6u));       // Start punct.
        inserts.push(sus::tuple(pos + 5u, 0u));  // End punct.
        pos += 5u;
        continue;
      }
      if (view.substr(pos, 4u) == "&lt;") {
        inserts.push(sus::tuple(pos, 6u));       // Start punct.
        inserts.push(sus::tuple(pos + 4u, 0u));  // End punct.
        pos += 4u;
        continue;
      }
      if (view.substr(pos, 4u) == "&gt;") {
        inserts.push(sus::tuple(pos, 6u));       // Start punct.
        inserts.push(sus::tuple(pos + 4u, 0u));  // End punct.
        pos += 4u;
        continue;
      }

      pos += 1u;
    }
  }

  if (!inserts.is_empty()) {
    inserts.sort_unstable();
    usize chars_inserted;
    for (auto [insert_at, index] : inserts) {
      str.insert(insert_at + chars_inserted, INSERTS[index]);
      chars_inserted += INSERTS[index].size();
    }
  }
}

// MD4C Callback functions

tainted_md4c<int> process_output(rlbox_sandbox_md4c& _, tainted_md4c<const MD_CHAR*> tainted_chars, tainted_md4c<MD_SIZE> tainted_size, __attribute__((unused)) tainted_md4c<void*> v) {
  if (!userdata) {
    return -1;
  }

  MD_SIZE size = tainted_size.unverified_safe_because(
      "Used to read some amount of tainted_chars."
      "Similar to the reasoning in copy_and_verify_string:"
      "in the worst case we will be copying all of the"
      "memory out of the sandbox, but it will never be"
      "outside the sandbox's range."
  );

  // We assume the recovered char array is NULL free, so we copy it as a string.
  int ret = tainted_chars.copy_and_verify_range([](std::unique_ptr<MD_CHAR[]> chars) {
    if (!chars) {
      std::string msg = fmt::format("[process_output] recovered char array is null");
      userdata->error_message = sus::some(sus::move(msg));
      return -1;
    }
    // Create the string up to some size
    userdata->parsed << std::string_view(chars.get(), size);
    return 0;
  }, size);

  return ret;
}

tainted_md4c<int> render_self_link(rlbox_sandbox_md4c& sandbox, tainted_md4c<const MD_CHAR*> tainted_chars, tainted_md4c<MD_SIZE> tainted_size, 
                            __attribute__((unused)) tainted_md4c<void*> v, tainted_md4c<MD_HTML*> tainted_html) {
  if (!userdata) {
    return -1;
  }

  std::string mapped;

  // We assume the recovered char array is NULL free, so we copy it as a string.
  int result = tainted_chars.copy_and_verify_string([tainted_size, &mapped](std::unique_ptr<MD_CHAR[]> chars) {
    if (!chars) {
      std::string msg = fmt::format("[render_self_link] recovered char array is null");
      userdata->error_message = sus::some(sus::move(msg));
      return -1;
    }
    // Verify the recovered size is less than the string length
    auto recovered_size = tainted_size.unverified_safe_because("used in comparision");
    auto size = std::strlen(chars.get());
    if (recovered_size > size) {
      std::string msg =
        fmt::format("[render_self_link] the claimed size ({}) is greater than the string size ({})", recovered_size, size);
      userdata->error_message = sus::some(sus::move(msg));
      return -1;
    }
    // Copy the string and length
    mapped = std::string(std::string_view(chars.get(), recovered_size));
    return 0;
  });
  if (result != 0) return result;

  auto count = 0_u32;
  if (auto it = userdata->page_state.self_link_counts.find(mapped);
      it != userdata->page_state.self_link_counts.end()) {
    count = it->second;
  }

  for (char& c : mapped) {
    if (c == ' ') {
      c = '-';
    } else {
      // SAFETY: The input is a char, so tolower will give a value in the
      // range of char.
      c = sus::cast<char>(std::tolower(c));
   }
  }

  size_t size = mapped.length();
  result = 0;
  auto tainted_mapped = sandbox.malloc_in_sandbox<MD_CHAR>(size);
  mapped.copy(tainted_mapped.unverified_safe_pointer_because(size, "writing to region"), mapped.length(), 0);

  result = sandbox.invoke_sandbox_function(render_url_escaped, tainted_html, tainted_mapped, size).unverified_safe_because("Result is checked.");

  if (result != 0) return result;
  if (count > 0u) {
    auto cur_char = sandbox.malloc_in_sandbox<MD_CHAR>(2);
    cur_char[0] = '-';
    cur_char[1] = '\0';
    result = sandbox.invoke_sandbox_function(render_url_escaped, tainted_html, cur_char, 1).unverified_safe_because("Result is checked.");
   if (result != 0) return result;
    while (count > 0u) {
      static const char NUMS[] = "0123456789";
      auto val = NUMS + (count % 10u);
      cur_char[0] = *val;
      cur_char[1] = '\0';
      result = sandbox.invoke_sandbox_function(render_url_escaped, tainted_html, cur_char, 1u).unverified_safe_because("Result is checked.");
   if (result != 0) return result;
      count /= 10u;
   }
  }
  return result;
}

tainted_md4c<int> record_self_link(rlbox_sandbox_md4c& _, tainted_md4c<const MD_CHAR*> tainted_chars, tainted_md4c<MD_SIZE> tainted_size, 
                            __attribute__((unused)) tainted_md4c<void*> v) {
  if (!userdata) {
    return -1;
  }

  std::string mapped;

  // We assume the recovered char array is NULL free, so we copy it as a string.
  int result = tainted_chars.copy_and_verify_string([tainted_size, &mapped](std::unique_ptr<MD_CHAR[]> chars) {
    if (!chars) {
      std::string msg = fmt::format("[record_self_link] recovered char array is null");
      userdata->error_message = sus::some(sus::move(msg));
      return -1;
    }
    // Verify the recovered size is less than the string length
    auto recovered_size = tainted_size.unverified_safe_because("used in comparision");
    auto size = std::strlen(chars.get());
    if (recovered_size > size) {
      std::string msg =
        fmt::format("[record_self_link] the claimed size ({}) is greater than the string size ({})", recovered_size, size);
      userdata->error_message = sus::some(sus::move(msg));
      return -1;
    }
    // Copy the string and length
    mapped = std::string(std::string_view(chars.get(), recovered_size));
    return 0;
  });
  if (result != 0) return result;

  if (auto it = userdata->page_state.self_link_counts.find(mapped);
      it != userdata->page_state.self_link_counts.end()) {
    it->second += 1u;
  } else {
    userdata->page_state.self_link_counts.emplace(sus::move(mapped), 1u);
  }
  return 0;
}

tainted_md4c<int> render_code_link(rlbox_sandbox_md4c& sandbox, tainted_md4c<const MD_CHAR*> tainted_chars, tainted_md4c<MD_SIZE> tainted_size, 
                            __attribute__((unused)) tainted_md4c<void*> v, tainted_md4c<MD_HTML*> tainted_html) {
  if (!userdata) {
    return -1;
  }

  std::string name;

    // We assume the recovered char array is NULL free, so we copy it as a string.
  int result = tainted_chars.copy_and_verify_string([tainted_size, &name](std::unique_ptr<MD_CHAR[]> chars) {
    if (!chars) {
      std::string msg = fmt::format("[render_code_link] recovered char array is null");
      userdata->error_message = sus::some(sus::move(msg));
      return -1;
    }
    // Verify the recovered size is less than the string length
    auto recovered_size = tainted_size.unverified_safe_because("used in comparision");
    auto size = std::strlen(chars.get());
    if (recovered_size > size) {
      std::string msg =
        fmt::format("[render_code_link] the claimed size ({}) is greater than the string size ({})", recovered_size, size);
      userdata->error_message = sus::some(sus::move(msg));
      return -1;
    }
    // Copy the string and length
    name = std::string(std::string_view(chars.get(), recovered_size));
    return 0;
  });
  if (result != 0) return result;

  auto anchor = std::string_view();
  if (auto pos = name.find('#'); pos != std::string_view::npos) {
    anchor = name.substr(pos);
    name = name.substr(0u, pos);
  }
  sus::Option<FoundName> found = userdata->page_state.db.find_name(name);
  if (found.is_some()) {
    std::string href;
    switch (found.as_value()) {
      case FoundName::Tag::Namespace:
        href = construct_html_url_for_namespace(
            found.as_value().as<FoundName::Tag::Namespace>());
        break;
      case FoundName::Tag::Function: {
        href = construct_html_url_for_function(
            found.as_value().as<FoundName::Tag::Function>());
        break;
      }
      case FoundName::Tag::Type:
        href = construct_html_url_for_type(
            found.as_value().as<FoundName::Tag::Type>());
        break;

      case FoundName::Tag::Concept:
        href = construct_html_url_for_concept(
            found.as_value().as<FoundName::Tag::Concept>());
        break;
      case FoundName::Tag::Field:
        href = construct_html_url_for_field(
            found.as_value().as<FoundName::Tag::Field>());
        break;
   }
    auto tainted_href_data = sandbox.malloc_in_sandbox<MD_CHAR>(href.size());
    memcpy(tainted_href_data.unverified_safe_pointer_because(href.size(), "writing to region"), href.data(), href.size());
    int r = sandbox.invoke_sandbox_function(render_url_escaped, tainted_html, tainted_href_data, href.size()).unverified_safe_because("Result is checked.");
    if (r != 0) return r;
    if (anchor.size() > 0u) {
      auto tainted_anchor_data = sandbox.malloc_in_sandbox<MD_CHAR>(anchor.size());
      memcpy(tainted_anchor_data.unverified_safe_pointer_because(anchor.size(), "writing to region"), anchor.data(), anchor.size());
      r = sandbox.invoke_sandbox_function(render_url_escaped, tainted_html, tainted_anchor_data, anchor.size()).unverified_safe_because("Result is checked.");
   }
    return r;
  } else {
    std::string msg =
        fmt::format("unable to resolve code link '{}' to a C++ name", name);
    if (userdata->page_state.options.ignore_bad_code_links) {
      fmt::println("WARNING: {}", msg);
      return 0;
   } else {
      userdata->error_message = sus::some(sus::move(msg));
      return -1;
   }
  }
}

}  // namespace

sus::Result<MarkdownToHtml, MarkdownToHtmlError> markdown_to_html(
    const Comment& comment, ParseMarkdownPageState& page_state) noexcept {

  // Declare and create a new sandbox
  rlbox_sandbox_md4c sandbox;
  sandbox.create_sandbox();

  std::ostringstream parsed;

  UserData data(parsed, page_state, sus::none());
  userdata = &data;

  auto input = comment.text.data();
  MD_SIZE input_size = u32::try_from(comment.text.size()).unwrap();

  tainted_md4c<MD_CHAR*> tainted_input = sandbox.malloc_in_sandbox<MD_CHAR>(input_size);
  if (!tainted_input) {
    return sus::err(MarkdownToHtmlError{
          .message = fmt::format("Failed to allocate sandbox memory")});
  }
  strncpy(tainted_input.unverified_safe_pointer_because(input_size, "writing to region"), input, input_size);

  auto process_output_cb = sandbox.register_callback(process_output);
  auto render_self_link_cb = sandbox.register_callback(render_self_link);
  auto record_self_link_cb = sandbox.register_callback(record_self_link);
  auto render_code_link_cb = sandbox.register_callback(render_code_link);

  auto tainted_callbacks = sandbox.malloc_in_sandbox<MD_HTML_CALLBACKS>();
  tainted_callbacks->process_output   = process_output_cb;
  tainted_callbacks->render_self_link = render_self_link_cb;
  tainted_callbacks->record_self_link = record_self_link_cb;
  tainted_callbacks->render_code_link = render_code_link_cb;

  unsigned parser_flags = MD_FLAG_PERMISSIVEAUTOLINKS | MD_FLAG_TABLES | MD_FLAG_STRIKETHROUGH |
          // Forked extensions.
          MD_FLAG_HEADERSELFLINKS | MD_FLAG_CODELINKS;

  // We enable MD_ASSERT() to catch memory safety bugs, so
  // ensure something gets printed should a problem occur.
  unsigned renderer_flags = MD_HTML_FLAG_DEBUG;

  int result = sandbox.invoke_sandbox_function(
      md_html,
      tainted_input, input_size,
      tainted_callbacks,
      nullptr, // userdata only used in callbacks, so we keep it as a local variable
      parser_flags,
      renderer_flags)
    .unverified_safe_because("Result is checked.");

  // Remove the sandbox components we created
  sandbox.free_in_sandbox(tainted_input);
  sandbox.free_in_sandbox(tainted_callbacks);

  process_output_cb.unregister();
  render_self_link_cb.unregister();
  record_self_link_cb.unregister();
  render_code_link_cb.unregister();
  sandbox.destroy_sandbox();

  if (result != 0) {
    if (userdata->error_message.is_some()) {
      auto error_message = userdata->error_message.take().unwrap();
      userdata = nullptr;
      return sus::err(
          MarkdownToHtmlError{.message = error_message});
    } else {
      userdata = nullptr;
      return sus::err(MarkdownToHtmlError{
          .message = fmt::format("unknown parsing error '{}'", result)});
    }
  }

  userdata = nullptr;
  std::string str = sus::move(parsed).str();
  apply_syntax_highlighting(str);

  return sus::ok(MarkdownToHtml{
      .full_html = sus::clone(str),
      .summary_html = summarize_html(str),
      .summary_text = drop_tags(summarize_html(str)),
  });
}

}  // namespace subdoc::gen
